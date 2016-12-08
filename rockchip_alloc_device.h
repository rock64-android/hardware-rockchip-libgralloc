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

#ifndef GRALLOC_ROCKCHIP_ALLOC_DEVICE_H_
#define GRALLOC_ROCKCHIP_ALLOC_DEVICE_H_

int rockchip_get_handle_type_by_heap_mask(unsigned int heap_mask);
int rockchip_get_int_property(const char* pcProperty, const char* default_value);
int rockchip_log(int check);
int rockchip_set_version();
int rockchip_alloc_ion_open(private_module_t *m);
int rockchip_alloc_ion_close(private_module_t *m);
#endif
