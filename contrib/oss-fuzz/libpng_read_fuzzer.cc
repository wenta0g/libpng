
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


/* Generate random bytes.  This uses a boring repeatable algorithm and it
 * is implemented here so that it gives the same set of numbers on every
 * architecture.  It's a linear congruential generator (Knuth or Sedgewick
 * "Algorithms") but it comes from the 'feedback taps' table in Horowitz and
 * Hill, "The Art of Electronics" (Pseudo-Random Bit Sequences and Noise
 * Generation.)
 */
static void
make_random_bytes(png_uint_32* seed, void* pv, size_t size)
{
   png_uint_32 u0 = seed[0], u1 = seed[1];
   png_bytep bytes = (png_bytep) pv;

   /* There are thirty three bits, the next bit in the sequence is bit-33 XOR
    * bit-20.  The top 1 bit is in u1, the bottom 32 are in u0.
    */
   size_t i;
   for (i=0; i<size; ++i)
   {
      /* First generate 8 new bits then shift them in at the end. */
      png_uint_32 u = ((u0 >> (20-8)) ^ ((u1 << 7) | (u0 >> (32-7)))) & 0xff;
      u1 <<= 8;
      u1 |= u0 >> 24;
      u0 <<= 8;
      u0 |= u;
      *bytes++ = (png_byte)u;
   }

   seed[0] = u0;
   seed[1] = u1;
}

static void randomize(void *pv, size_t size)
{
   static png_uint_32 random_seed[2] = {0x56789abc, 0xd};
   make_random_bytes(random_seed, pv, size);
}

static png_byte
random_byte(void)
{
   unsigned char b1[1];
   randomize(b1, sizeof b1);
   return b1[0];
}


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
  //Image image;
  png_image image;
  memset(&image, 0, sizeof image);
  image.version = PNG_IMAGE_VERSION;

  /*Read from file version*/
  if (png_image_begin_read_from_memory(&image, data, size))
  {
    png_bytep buffer;
    image.format = (uint8_t) random_byte();
	  // image.format = PNG_FORMAT_GA;
    buffer = (unsigned char *) limited_malloc(PNG_IMAGE_SIZE(image));
    if (buffer != NULL)
    {
      if (png_image_finish_read(&image, NULL, buffer, 0, NULL))
      {
        //printf("read success\n");
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
    //printf("invalid filename\n");
    png_image_free(&image);
    return 0;
  }
/*
  //png_bytep b = data;
  png_const_bytep b;
  //png_bytep b;
  //image.input_memory = data;
  //image.input_memory_size = size;

  // Setting up reading from buffer.
  memcpy(b, data, size);
  //image.input_memory = b;
  //imge.input_memory = data + kPngHeaderSize;
  //image.input_memory->bytes_left = size - kPngHeaderSize;
  

  memset(&image, 0, sizeof *image);

  //memset(&image.image, 0, sizeof image.image);
  image.version = PNG_IMAGE_VERSION;
  
  if (!png_image_begin_read_from_memory(&image, b,
      size)){

      return 0;
  }
  image.format = PNG_FORMAT_RGB;
  png_bytep buffer;
  if (size > 8000000)
    {
      return 0;
    }
  else
  { 
  buffer = malloc(PNG_IMAGE_SIZE(image));
  }

  if (buffer != NULL)
  {
    if (!png_image_finish_read(&image, NULL, buffer, 0, NULL))
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
*/

  
}
