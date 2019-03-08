/*
 * json.c
 *
 *  Created on: 15 Mrt. 2018
 *      Author: heindekock
 */


/*
 * Simple example of parsing and printing JSON using jansson.
 *
 * SYNOPSIS:
 * $ examples/simple_parse
 * Type some JSON > [true, false, null, 1, 0.0, -0.0, "", {"name": "barney"}]
 * JSON Array of 8 elements:
 *   JSON True
 *   JSON False
 *   JSON Null
 *   JSON Integer: "1"
 *   JSON Real: 0.000000
 *   JSON Real: -0.000000
 *   JSON String: ""
 *   JSON Object of 1 pair:
 *     JSON Key: "name"
 *     JSON String: "barney"
 *
 * Copyright (c) 2014 Robert Poor <rdpoor@gmail.com>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "json.h"
#include "utils.h"

/* forward refs */
const char *json_plural   (int count);
void fprint_json_aux      (FILE *file, json_t *element);
void fprint_json_object   (FILE *file, json_t *element);
void fprint_json_array    (FILE *file, json_t *element);
void fprint_json_string   (FILE *file, json_t *element);
void fprint_json_integer  (FILE *file, json_t *element);
void fprint_json_real     (FILE *file, json_t *element);
void fprint_json_true     (FILE *file, json_t *element);
void fprint_json_false    (FILE *file, json_t *element);
void fprint_json_null     (FILE *file, json_t *element);

void fprint_json_aux (FILE *file, json_t *element)
{
  switch (json_typeof (element))
  {
    case JSON_OBJECT:     fprint_json_object  (file,element); return;
    case JSON_ARRAY:      fprint_json_array   (file,element); return;
    case JSON_STRING:     fprint_json_string  (file,element); return;
    case JSON_INTEGER:    fprint_json_integer (file,element); return;
    case JSON_REAL:       fprint_json_real    (file,element); return;
    case JSON_TRUE:       fprint_json_true    (file,element); return;
    case JSON_FALSE:      fprint_json_false   (file,element); return;
    case JSON_NULL:       fprint_json_null    (file,element); return;
    default: DEBUG_PRINTF("unrecognized JSON type %d", json_typeof (element));
  }

  return;
}

const char *json_plural(int count)
{
  return count == 1 ? "" : "s";
}

void fprint_json_object (FILE *file, json_t *element)
{
  const char *key;
  json_t *value;

  json_object_foreach (element, key, value)
  {
    fprint_json_aux (file, value);
  }
}

void fprint_json_array (FILE *file, json_t *element)
{
  size_t i;
  size_t size = json_array_size (element);

  for (i = 0; i < size; i++)
  {
    fprint_json_aux (file, json_array_get(element, i));
  }
}

void fprint_json_string (FILE *file, json_t *element)
{
  fprintf (file, "%s", json_string_value(element));
}

void fprint_json_integer (FILE *file, json_t *element)
{
  fprintf (file, "%" JSON_INTEGER_FORMAT "", json_integer_value(element));
}

void fprint_json_real (FILE *file, json_t *element)
{
  fprintf (file, "%f", json_real_value(element));
}

void fprint_json_true (FILE *file, json_t *element)
{
  (void)element;
  fprintf (file, "true");
}

void fprint_json_false (FILE *file, json_t *element)
{
  (void)element;
  fprintf (file, "false");
}

void fprint_json_null (FILE *file, json_t *element)
{
  (void)element;
//  fprintf (file, "");
}

/*
 * Parse text into a JSON object. If text is valid JSON, returns a
 * json_t structure, otherwise prints and error and returns null.
 */
json_t *load_json(const char *text)
{
  json_t *root;
  json_error_t error;

  root = json_loads(text, 0, &error);

  if (root)
  {
    return root;
  }
  else
  {
    fprintf(stderr, "json error on line %d: %s\n", error.line, error.text);
    return (json_t *)0;
  }
}

void load_json_string_value (json_t *root, char **dest, char *json_object, char *debug)
{
  json_t *object = json_object_get (root, json_object);

  if (object)
  {
    if (json_is_string(object))
    {
      if (strlen (json_string_value (object)))
      {
        if (*dest)
          free (*dest);

        *dest = strdup (json_string_value (object));

        if (debug && dest)
          DEBUG_PRINTF("%-40.40s : %-80.80s", debug, *dest);
      }

      //json_object_del(root, json_object);
    }

    //json_decref (object); this removes the json object so we cannot print it later for psign
  }
}

void load_json_object_value (json_t *root, char **dest, char *json_object, char *debug)
{
  json_t *object = json_object_get (root, json_object);

  if (object)
  {
    if (json_is_object (object))
    {
      if (*dest)
        free (*dest);

      *dest = json_dumps (object, JSON_ENSURE_ASCII | JSON_PRESERVE_ORDER | JSON_COMPACT);

      if (debug && dest)
        DEBUG_PRINTF("%-40.40s : %-80.80s", debug, *dest);
      //json_object_del(root, json_object);
    }

    //json_decref (object); this removes the json object so we cannot print it later for psign
  }
}

void load_json_integer_value (json_t *root, int *dest, int default_value, char *json_object, char *debug)
{
  json_t *object = json_object_get (root, json_object);

  *dest = default_value;

  if (object)
  {
    if (json_is_integer(object))
    {
      *dest = json_integer_value (object);
      if (debug)
        DEBUG_PRINTF("%-40.40s : %d", debug, *dest);

      //json_object_del(root, json_object);
    }

    //json_decref (object);
  }
}


