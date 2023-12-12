// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#pragma once

/* taken from driver/API_VERSION */
#define PPM_API_CURRENT_VERSION_MAJOR 6
#define PPM_API_CURRENT_VERSION_MINOR 0
#define PPM_API_CURRENT_VERSION_PATCH 0

/* taken from driver/SCHEMA_VERSION */
#define PPM_SCHEMA_CURRENT_VERSION_MAJOR 2
#define PPM_SCHEMA_CURRENT_VERSION_MINOR 12
#define PPM_SCHEMA_CURRENT_VERSION_PATCH 4

#include "ppm_api_version.h"

#define DRIVER_VERSION "6.1.0-372+60e5b74-driver"

#define DRIVER_NAME "scap"

#define DRIVER_DEVICE_NAME "scap"

#define DRIVER_COMMIT "60e5b748eaba4b7ee5d676c94e65b2d06ed6502f"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME DRIVER_NAME
#endif
