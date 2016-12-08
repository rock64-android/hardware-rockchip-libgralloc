/*
 * Copyright (C) 2016 ROCKCHIP Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include <cutils/log.h>
#include <cutils/atomic.h>
#include <cutils/properties.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>

#include <sys/ioctl.h>

#include "alloc_device.h"
#include "gralloc_priv.h"
#include "gralloc_helper.h"
#include "framebuffer_device.h"

#if GRALLOC_ARM_UMP_MODULE
#include <ump/ump.h>
#include <ump/ump_ref_drv.h>
#endif

#if GRALLOC_ARM_DMA_BUF_MODULE
#include <linux/ion.h>
#include <ion/ion.h>
#endif

/*
#define ION_HEAP_SYSTEM_MASK		(1 << ION_HEAP_TYPE_SYSTEM)
#define ION_HEAP_SYSTEM_CONTIG_MASK	(1 << ION_HEAP_TYPE_SYSTEM_CONTIG)
#define ION_HEAP_CARVEOUT_MASK		(1 << ION_HEAP_TYPE_CARVEOUT)
#define ION_HEAP_TYPE_DMA_MASK		(1 << ION_HEAP_TYPE_DMA)
#define ION_HEAP_TYPE_SECURE_MASK	(1 << ION_HEAP_TYPE_SECURE)
*/
int rockchip_get_handle_type_by_heap_mask(unsigned int heap_mask)
{
	int ret = 0;
	switch (heap_mask) {
#if defined(ION_HEAP_SECURE_MASK)
		case ION_HEAP_SECURE_MASK:
			ret = 0;
			break;
#endif
		case ION_HEAP_SYSTEM_MASK:
			ret = 1;
			break;
		case ION_HEAP_SYSTEM_CONTIG_MASK:
			ret = 1;
			break;
		case ION_HEAP_CARVEOUT_MASK:
			ret = 0;
			break;
		case ION_HEAP_TYPE_DMA_MASK:
			ret = 0;
			break;
#ifdef ION_HEAP_TYPE_SECURE_MASK
		case ION_HEAP_TYPE_SECURE_MASK:
			ret = 0;
			break;
#endif
		default:
			ALOGE("%s,%d err heap mask:%d", __func__, __LINE__, heap_mask);
			ret = 0;
			break;
	}

	return ret;
}

int rockchip_get_int_property(const char* pcProperty,
                                                  const char* default_value)
{
	char value[PROPERTY_VALUE_MAX];
	int new_value = 0;

	if (pcProperty == NULL || default_value == NULL)
	{
		return -1;
	}

	property_get(pcProperty, value, default_value);
	new_value = atoi(value);

	return new_value;
}

int rockchip_log(int check)
{
	static int log = 0;
	if (check)
		log = rockchip_get_int_property("sys.gralloc.log","0");
	return log;
}

int rockchip_alloc_ion_open(private_module_t *m)
{
	int ret = 0;
	if (!m) {
		AERR("private_module_t in is null m = %p", m);
		return -EINVAL;
	}

	if (m->ion_client <= 0) {
		m->ion_client = ion_open();

		if (m->ion_client < 0) {
			AERR("ion_open failed with %s", strerror(errno));
			ret = m->ion_client;
		} else {
			android_atomic_inc(&m->refCount);
			AINF(" ion device open success! fd = %d", m->ion_client);
		}
	} else {
		ret = 0;
		//AINF(" ion device already opened! fd = %d", m->ion_client);
		android_atomic_inc(&m->refCount);
	}

	return ret;
}

int rockchip_alloc_ion_close(private_module_t *m)
{
	int ret = 0;
	if (!m) {
		ret = -EINVAL;
		AERR("private_module_t in is null m = %p", m);
		return ret;
	}

	if (m->refCount > 0 && android_atomic_dec(&m->refCount) == 1) {
		if (m->ion_client > 0 && 0 != ion_close(m->ion_client)) {
			ret = -1;
			AERR("Failed to close ion_client: %d", m->ion_client);
		} else {
			ret = 0;
			//AINF(" ion de refCount = %d", m->refCount);
		}

		AINF(" ion device closed! fd = %d", m->ion_client);
		m->ion_client = -1;
	} else if (m->refCount < 0) {
		// Never expect this happen
		AERR("ion client ref count : %d", m->refCount);
		m->refCount = 0;
		ret = -1;
	} else {
		ret = 0;
		//AINF(" ion de refCount = %d", m->refCount);
	}

	return ret;
}
