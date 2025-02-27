
// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define PNG_INTERNAL
#include "png.h"


const uint8_t max = 19;
static const uint8_t format_names[max]={
  PNG_FORMAT_GRAY,
  PNG_FORMAT_GA,
  PNG_FORMAT_AG,
  PNG_FORMAT_RGB,
  PNG_FORMAT_BGR,
  PNG_FORMAT_RGBA,
  PNG_FORMAT_ARGB,
  PNG_FORMAT_BGRA,
  PNG_FORMAT_ABGR,
  PNG_FORMAT_LINEAR_Y,
  PNG_FORMAT_LINEAR_Y_ALPHA,
  PNG_FORMAT_LINEAR_RGB,
  PNG_FORMAT_LINEAR_RGB_ALPHA,
  PNG_FORMAT_RGB_COLORMAP,
  PNG_FORMAT_BGR_COLORMAP,
  PNG_FORMAT_RGBA_COLORMAP,
  PNG_FORMAT_ARGB_COLORMAP,
  PNG_FORMAT_BGRA_COLORMAP,
  PNG_FORMAT_ABGR_COLORMAP
};



void* limited_malloc(png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount. This allocator used to be in the Chromium
  // version of this fuzzer.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

static const int kPngHeaderSize = 8;

// Entry point for LibFuzzer.
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter13.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  std::vector<unsigned char> v(data, data + size);
  if (png_sig_cmp(v.data(), 0, kPngHeaderSize)) {
    // not a PNG.
    return 0;
  }
  png_image image;
  memset(&image, 0, sizeof image);
  image.version = PNG_IMAGE_VERSION;

  /*Read from file version*/
  if (png_image_begin_read_from_memory(&image, data, size))
  {
    png_bytep buffer;
    /*  Use the input file to generate an image format,
     to trigger some transformations from the input file to the read buffer*/
    const uint8_t* temp_data = data;
    if (size < kPngHeaderSize + 4){
      return 0;
    }
	  
    if (size <= 400)
    {
      image.format = PNG_FORMAT_RGB;//default
    }
    else
    {
      image.format = format_names[(*(temp_data + 400)) % max];
    }
	  
    buffer = (unsigned char *) limited_malloc(PNG_IMAGE_SIZE(image));
    if (buffer != NULL)
    {
      if (png_image_finish_read(&image, NULL, buffer, 0, NULL))
      {
        free(buffer);
	      png_image_free(&image);
        return 0;
      }
      else
      {
        free(buffer);
	      png_image_free(&image);
        return 0;
      }
    }
    else
    {
	      free(buffer);
        png_image_free(&image);
        return 0;
    }

  }
  else
  {
    png_image_free(&image);
    return 0;
  }
}
