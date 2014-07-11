/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <pthread.h>

#include <cutils/log.h>
#include <cutils/atomic.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>

#include "gralloc_priv.h"
#include "alloc_device.h"
#include "framebuffer_device.h"

#include "gralloc_module_allocator_specific.h"
#include <cutils/properties.h>

#include <fcntl.h>

#define RK_FBIOGET_IOMMU_STA        0x4632

#define RK_GRALLOC_VERSION "1.001"

static pthread_mutex_t s_map_lock = PTHREAD_MUTEX_INITIALIZER;
int g_MMU_stat = 0;

static int gralloc_device_open(const hw_module_t* module, const char* name, hw_device_t** device)
{
	int status = -EINVAL;
    int fd;
    property_set("sys.ggralloc.version", RK_GRALLOC_VERSION);

    fd = open("/dev/graphics/fb0", O_RDONLY, 0);
    if(fd > 0)
    {
	    ioctl(fd, RK_FBIOGET_IOMMU_STA, &g_MMU_stat);
	    close(fd);
    }
    else
    {
        ALOGE("gralloc_debug fb0 open err in gralloc_device_open!");
    }

	if (!strcmp(name, GRALLOC_HARDWARE_GPU0))
	{
		status = alloc_device_open(module, name, device);
	}
	else if (!strcmp(name, GRALLOC_HARDWARE_FB0))
	{
		status = framebuffer_device_open(module, name, device);
	}


	return status;
}

static int gralloc_register_buffer(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Registering invalid buffer 0x%x, returning error", (int)handle);
		return -EINVAL;
	}

	// if this handle was created in this process, then we keep it as is.
	private_handle_t* hnd = (private_handle_t*)handle;

	if (hnd->pid == getpid())
	{
		// If the handle is created and registered in the same process this is valid,
		// but it could also be that application is registering twice which is illegal.
		AWAR("Registering handle 0x%x coming from the same process: %d.", (unsigned int)hnd, hnd->pid);
	}

	int retval = -EINVAL;

	pthread_mutex_lock(&s_map_lock);

	hnd->pid = getpid();

	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER) 
	{
		AERR( "Can't register buffer 0x%x as it is a framebuffer", (unsigned int)handle );
	}
	else if (hnd->flags & (private_handle_t::PRIV_FLAGS_USES_UMP |
	                       private_handle_t::PRIV_FLAGS_USES_ION))
	{
		retval = gralloc_backend_register(hnd);
	}
	else
	{
		AERR("registering non-UMP buffer not supported. flags = %d", hnd->flags );
	}

	pthread_mutex_unlock(&s_map_lock);
	return retval;
}

static int gralloc_unregister_buffer(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("unregistering invalid buffer 0x%x, returning error", (int)handle);
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;

	AERR_IF(hnd->lockState & private_handle_t::LOCK_STATE_READ_MASK, "[unregister] handle %p still locked (state=%08x)", hnd, hnd->lockState);

	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER)
	{
		AERR( "Can't unregister buffer 0x%x as it is a framebuffer", (unsigned int)handle );
	}
	else if (hnd->pid == getpid()) // never unmap buffers that were not created in this process
	{
		pthread_mutex_lock(&s_map_lock);

		if (hnd->flags & (private_handle_t::PRIV_FLAGS_USES_UMP |
		                  private_handle_t::PRIV_FLAGS_USES_ION))
		{
			gralloc_backend_unregister(hnd);
		}
		else
		{
			AERR("Unregistering unknown buffer is not supported. Flags = %d", hnd->flags);
		}

		hnd->base = 0;
		hnd->lockState  = 0;
		hnd->writeOwner = 0;

		pthread_mutex_unlock(&s_map_lock);
	}
	else
	{
		AERR( "Trying to unregister buffer 0x%x from process %d that was not created in current process: %d", (unsigned int)hnd, hnd->pid, getpid());
	}

	return 0;
}

static int gralloc_lock(gralloc_module_t const* module, buffer_handle_t handle, int usage, int l, int t, int w, int h, void** vaddr)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Locking invalid buffer 0x%x, returning error", (int)handle );
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;
	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP || hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
	{
		hnd->writeOwner = usage & GRALLOC_USAGE_SW_WRITE_MASK;
	}
	if (usage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK))
	{
		*vaddr = (void*)hnd->base;
	}
	return 0;
}

static int gralloc_unlock(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR( "Unlocking invalid buffer 0x%x, returning error", (int)handle );
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;

	if (hnd->flags & (private_handle_t::PRIV_FLAGS_USES_UMP |
	                  private_handle_t::PRIV_FLAGS_USES_ION)
	    && hnd->writeOwner)
	{
		gralloc_backend_sync(hnd);
	}

	return 0;
}

// There is one global instance of the module

static struct hw_module_methods_t gralloc_module_methods =
{
	open: gralloc_device_open
};

private_module_t::private_module_t()
{
#define INIT_ZERO(obj) (memset(&(obj),0,sizeof((obj))))

	base.common.tag = HARDWARE_MODULE_TAG;
	base.common.version_major = 1;
	base.common.version_minor = 0;
	base.common.id = GRALLOC_HARDWARE_MODULE_ID;
	base.common.name = "Graphics Memory Allocator Module";
	base.common.author = "ARM Ltd.";
	base.common.methods = &gralloc_module_methods;
	base.common.dso = NULL;
	INIT_ZERO(base.common.reserved);

	base.registerBuffer = gralloc_register_buffer;
	base.unregisterBuffer = gralloc_unregister_buffer;
	base.lock = gralloc_lock;
	base.unlock = gralloc_unlock;
	base.perform = NULL;
	INIT_ZERO(base.reserved_proc);

	framebuffer = NULL;
	flags = 0;
	numBuffers = 0;
	bufferMask = 0;
	pthread_mutex_init(&(lock), NULL);
	currentBuffer = NULL;
	INIT_ZERO(info);
	INIT_ZERO(finfo);
	xdpi = 0.0f; 
	ydpi = 0.0f; 
	fps = 0.0f; 

#undef INIT_ZERO
};

/*
 * HAL_MODULE_INFO_SYM will be initialized using the default constructor
 * implemented above
 */ 
struct private_module_t HAL_MODULE_INFO_SYM;

