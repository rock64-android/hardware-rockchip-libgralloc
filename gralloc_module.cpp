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

// #define ENABLE_DEBUG_LOG
#include <log/custom_log.h>

#include <errno.h>
#include <pthread.h>

#include <cutils/log.h>
#include <cutils/atomic.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>

#include <vector>

#include "gralloc_priv.h"
#include "gralloc_helper.h"
#include "alloc_device.h"
#include "framebuffer_device.h"

#include "gralloc_module_allocator_specific.h"

#if MALI_AFBC_GRALLOC == 1
#include "gralloc_buffer_priv.h"
#endif

#include "format_chooser.h"

#include <cutils/properties.h>

#include <fcntl.h>

#define RK_FBIOGET_IOMMU_STA        0x4632

#define RK_GRALLOC_VERSION "1.0.3"
#define ARM_RELEASE_VER "r11p0-00rel0"

static pthread_mutex_t s_map_lock = PTHREAD_MUTEX_INITIALIZER;
int g_MMU_stat = 0;

static int gralloc_device_open(const hw_module_t* module, const char* name, hw_device_t** device)
{
	int status = -EINVAL;
    int fd;
    property_set("sys.ggralloc.version", RK_GRALLOC_VERSION);

    I("to open device '%s' in gralloc_module with ver '%s' on arm_release_ver '%s', built at '%s', on '%s'.",
        name,
        RK_GRALLOC_VERSION,
        ARM_RELEASE_VER,
        __TIME__,
        __DATE__);

    fd = open("/dev/graphics/fb0", O_RDONLY, 0);
    ALOGD("gralloc_device_open new neiw fd=%d",fd);
    if(fd > 0)
    {
	    ioctl(fd, RK_FBIOGET_IOMMU_STA, &g_MMU_stat);
        ALOGD("g_MMU_stat=%d",g_MMU_stat);
	    close(fd);
    }
    else
    {
        ALOGE("gralloc_debug fb0 open err in gralloc_device_open!");
    }
	if (!strncmp(name, GRALLOC_HARDWARE_GPU0, MALI_GRALLOC_HARDWARE_MAX_STR_LEN))
	{
		status = alloc_device_open(module, name, device);
	}
	else if (!strncmp(name, GRALLOC_HARDWARE_FB0, MALI_GRALLOC_HARDWARE_MAX_STR_LEN))
	{
		status = framebuffer_device_open(module, name, device);
	}

	return status;
}

static int gralloc_register_buffer(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Registering invalid buffer %p, returning error", handle);
		return -EINVAL;
	}

	// if this handle was created in this process, then we keep it as is.
	private_handle_t* hnd = (private_handle_t*)handle;

	if (hnd->pid == getpid())
	{
		// If the handle is created and registered in the same process this is valid,
		// but it could also be that application is registering twice which is illegal.
		AWAR("Registering handle %p coming from the same process: %d.", hnd, hnd->pid);
	}

	int retval = -EINVAL;

	pthread_mutex_lock(&s_map_lock);

	hnd->pid = getpid();

	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER) 
	{
		AERR( "Can't register buffer %p as it is a framebuffer", handle );
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
		AERR("unregistering invalid buffer %p, returning error", handle);
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;

	AERR_IF(hnd->lockState & private_handle_t::LOCK_STATE_READ_MASK, "[unregister] handle %p still locked (state=%08x)", hnd, hnd->lockState);

	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER)
	{
		AERR( "Can't unregister buffer %p as it is a framebuffer", handle );
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

#if MALI_AFBC_GRALLOC == 1
		/*
		 * Close shared attribute region file descriptor. It might seem strange to "free"
		 * this here since this can happen in a client process, but free here is nothing
		 * but unmapping and closing the duplicated file descriptor. The original ashmem
		 * fd instance is still open until alloc_device_free() is called. Even sharing
		 * of gralloc buffers within the same process should have fds dup:ed.
		 */
		gralloc_buffer_attr_free( hnd );

#endif
		hnd->base = 0;
		hnd->lockState  = 0;
		hnd->writeOwner = 0;

		pthread_mutex_unlock(&s_map_lock);
	}
	else
	{
		AERR( "Trying to unregister buffer %p from process %d that was not created in current process: %d", hnd, hnd->pid, getpid());
	}

	return 0;
}

static int gralloc_lock(gralloc_module_t const* module, buffer_handle_t handle, int usage, int l, int t, int w, int h, void** vaddr)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Locking invalid buffer %p, returning error", handle );
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;

	if (hnd->req_format == HAL_PIXEL_FORMAT_YCbCr_420_888)
	{
		AERR("Buffers with format YCbCr_420_888 must be locked using (*lock_ycbcr)" );
		return -EINVAL;
	}

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

static int gralloc_lock_ycbcr(gralloc_module_t const* module, buffer_handle_t handle, int usage,
                              int l, int t, int w, int h,
                              android_ycbcr *ycbcr)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Locking invalid buffer %p, returning error", handle );
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;

	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP || hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
	{
		hnd->writeOwner = usage & GRALLOC_USAGE_SW_WRITE_MASK;
	}
	if (usage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK))
	{
		char* base = (char*)hnd->base;
		int y_stride = hnd->byte_stride;
		int y_size =  y_stride * hnd->height;

		int u_offset = 0;
		int v_offset = 0;
		int c_stride = 0;
		int step = 0;

		/* map format if necessary */
		uint64_t mapped_format = map_format(hnd->internal_format & GRALLOC_ARM_INTFMT_FMT_MASK);

		switch (mapped_format)
		{
			case GRALLOC_ARM_HAL_FORMAT_INDEXED_NV12:
				c_stride = y_stride;
				/* Y plane, UV plane */
				u_offset = y_size;
				v_offset = y_size + 1;
				step = 2;
				break;

			case GRALLOC_ARM_HAL_FORMAT_INDEXED_NV21:
				c_stride = y_stride;
				/* Y plane, UV plane */
				v_offset = y_size;
				u_offset = y_size + 1;
				step = 2;
				break;

			case HAL_PIXEL_FORMAT_YV12:
			case GRALLOC_ARM_HAL_FORMAT_INDEXED_YV12:
			{
				int c_size;

				/* Stride alignment set to 16 as the SW access flags were set */
				c_stride = GRALLOC_ALIGN(hnd->byte_stride / 2, 16);
				c_size = c_stride * (hnd->height / 2);
				/* Y plane, V plane, U plane */
				v_offset = y_size;
				u_offset = y_size + c_size;
				step = 1;
				break;
			}

			default:
				AERR("Can't lock buffer %p: wrong format %llx", hnd, hnd->internal_format);
				return -EINVAL;
		}

		ycbcr->y = base;
		ycbcr->cb = base + u_offset;
		ycbcr->cr = base + v_offset;
		ycbcr->ystride = y_stride;
		ycbcr->cstride = c_stride;
		ycbcr->chroma_step = step;
	}
	return 0;
}

static int gralloc_unlock(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR( "Unlocking invalid buffer %p, returning error", handle );
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

static int gralloc_perform(gralloc_module_t const* module, int op, ...)
{
	va_list args;
	int err;

	va_start(args, op);
	switch (op) {
		case GRALLOC_MODULE_PERFORM_GET_HADNLE_PRIME_FD:
		{
			buffer_handle_t handle = va_arg(args, buffer_handle_t);
			int *fd = va_arg(args, int *);

			err = private_handle_t::validate(handle);

			if (fd == NULL)
				err = -EINVAL;

			if (err != 0)
				break;

			private_handle_t* hnd = (private_handle_t*)handle;
			err = gralloc_backend_get_fd(hnd,fd);
		}
		break;

		case GRALLOC_MODULE_PERFORM_GET_HADNLE_ATTRIBUTES:
		{
			buffer_handle_t handle = va_arg(args, buffer_handle_t);
			std::vector<int> *attrs = va_arg(args, std::vector<int> *);

			err = private_handle_t::validate(handle);

			if (attrs == NULL)
				err = -EINVAL;

			if (err != 0)
				break;

			private_handle_t* hnd = (private_handle_t*)handle;
			err = gralloc_backend_get_attrs(hnd, (void*)attrs);
		}
		break;

		default:
			err = -EINVAL;
		break;
	}
	va_end(args);

	return err;
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
	base.lock_ycbcr = gralloc_lock_ycbcr;
	base.perform = gralloc_perform;
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
	swapInterval = 1;

	initialize_blk_conf();

#undef INIT_ZERO
};

/*
 * HAL_MODULE_INFO_SYM will be initialized using the default constructor
 * implemented above
 */ 
struct private_module_t HAL_MODULE_INFO_SYM;

