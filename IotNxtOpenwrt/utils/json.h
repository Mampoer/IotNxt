/*
 * json.h
 *
 *  Created on: 15 Mrt. 2018
 *      Author: heindekock
 */

#ifndef JSON_H_
#define JSON_H_

#include <stdarg.h>
#include <stdbool.h>
#include <jansson.h>

/* forward refs */
void print_json (json_t *root);
void print_json_aux (json_t *element, int indent);
void print_json_indent (int indent);
const char *json_plural (int count);
void print_json_object (json_t *element, int indent);
void print_json_array (json_t *element, int indent);
void print_json_string (json_t *element, int indent);
void print_json_integer (json_t *element, int indent);
void print_json_real (json_t *element, int indent);
void print_json_true (json_t *element, int indent);
void print_json_false (json_t *element, int indent);
void print_json_null (json_t *element, int indent);

json_t *load_json (const char *text);

void load_json_string_value  (json_t *root, char **dest, char *json_object, char *debug);
void load_json_object_value  (json_t *root, char **dest, char *json_object, char *debug);
void load_json_integer_value (json_t *root, int   *dest, int default_value, char *json_object, char *debug );


#endif /* JSON_H_ */
