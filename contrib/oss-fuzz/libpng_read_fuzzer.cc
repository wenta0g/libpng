
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

#define PNG_CLEANUP \
  if(png_handler.png_ptr) \
  { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        &png_handler.end_info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        nullptr); \
    else \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr); \
    png_handler.png_ptr = nullptr; \
    png_handler.row_ptr = nullptr; \
    png_handler.info_ptr = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

/* THE Image STRUCTURE */
/* The super-class of a png_image, contains the decoded image plus the input
 * data necessary to re-read the file with a different format.
 */
typedef struct
{
   png_image   image;
   png_uint_32 opts;
   png_voidp   input_memory;
   size_t      input_memory_size;
   png_bytep   buffer;
   size_t      bufsize;
   size_t      allocsize;
   char        tmpfile_name[32];
   png_uint_16 colormap[256*4];
}
Image;



/* Initializer: also sets the permitted error limit for 16-bit operations. */
static void
newimage(Image *image)
{
   memset(image, 0, sizeof *image);
}


/* Delete function; cleans out all the allocated data and the temporary file in
 * the image.
 */
static void
freeimage(Image *image)
{
   //freebuffer(image);
   png_image_free(&image->image);
   //free(image->buffer);
   //image->buffer = NULL;
   if (image->input_memory != NULL)
   {
      free(image->input_memory);
      image->input_memory = NULL;
      image->input_memory_size = 0;
   }

}




void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

void* limited_malloc(png_structp, png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount. This allocator used to be in the Chromium
  // version of this fuzzer.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  return free(ptr);
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
  Image image;

  //png_bytep b = data;
  png_bytep b;
  //image.input_memory = data;
  image.input_memory_size = size;

  // Setting up reading from buffer.
  memcpy(b, data, size);
  image.input_memory = b;
  //imge.input_memory = data + kPngHeaderSize;
  //image.input_memory->bytes_left = size - kPngHeaderSize;
  
  memset(&image.image, 0, sizeof image.image);
  image.image.version = PNG_IMAGE_VERSION;
  
  if (!png_image_begin_read_from_memory(&image.image, image.input_memory,
      image.input_memory_size)){

      return 0;
  }
  
  png_bytep buffer;
  if (size > 8000000)
    {
      return 0;
    }
  else
  { 
  buffer = (unsigned char *) malloc(size);
  }

  if (buffer != NULL)
  {
    if (!png_image_finish_read(&image.image, NULL, buffer, 0, NULL))
    {
      return 0;
    }
    free(buffer);

  }
  else
  {
    freeimage(&image);
    
    //png_image_free(&image);
    return 0;
  }
  freeimage(&image);
  free(buffer);
  //png_image_free(&image);
  return 0;
}
