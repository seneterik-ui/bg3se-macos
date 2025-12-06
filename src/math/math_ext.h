/**
 * math_ext.h - Ext.Math API Header
 *
 * Vector, matrix, and math utilities matching Windows BG3SE API.
 */

#ifndef MATH_EXT_H
#define MATH_EXT_H

#include <lua.h>
#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// Vector Types
// ============================================================================

typedef struct {
    float x, y;
} vec2;

typedef struct {
    float x, y, z;
} vec3;

typedef struct {
    float x, y, z, w;
} vec4;

// ============================================================================
// Matrix Types (column-major for OpenGL compatibility)
// ============================================================================

typedef struct {
    float m[9];  // 3x3 matrix, column-major
} mat3;

typedef struct {
    float m[16]; // 4x4 matrix, column-major
} mat4;

// ============================================================================
// Vector Operations
// ============================================================================

// vec2
vec2 vec2_add(vec2 a, vec2 b);
vec2 vec2_sub(vec2 a, vec2 b);
vec2 vec2_mul(vec2 a, float s);
vec2 vec2_div(vec2 a, float s);
float vec2_dot(vec2 a, vec2 b);
float vec2_length(vec2 v);
vec2 vec2_normalize(vec2 v);
float vec2_distance(vec2 a, vec2 b);
float vec2_angle(vec2 a, vec2 b);

// vec3
vec3 vec3_add(vec3 a, vec3 b);
vec3 vec3_sub(vec3 a, vec3 b);
vec3 vec3_mul(vec3 a, float s);
vec3 vec3_div(vec3 a, float s);
float vec3_dot(vec3 a, vec3 b);
vec3 vec3_cross(vec3 a, vec3 b);
float vec3_length(vec3 v);
vec3 vec3_normalize(vec3 v);
float vec3_distance(vec3 a, vec3 b);
float vec3_angle(vec3 a, vec3 b);
vec3 vec3_reflect(vec3 i, vec3 n);
vec3 vec3_project(vec3 v, vec3 normal);
vec3 vec3_perpendicular(vec3 v, vec3 normal);
vec3 vec3_lerp(vec3 a, vec3 b, float t);

// vec4
vec4 vec4_add(vec4 a, vec4 b);
vec4 vec4_sub(vec4 a, vec4 b);
vec4 vec4_mul(vec4 a, float s);
vec4 vec4_div(vec4 a, float s);
float vec4_dot(vec4 a, vec4 b);
float vec4_length(vec4 v);
vec4 vec4_normalize(vec4 v);
float vec4_distance(vec4 a, vec4 b);
vec4 vec4_lerp(vec4 a, vec4 b, float t);

// ============================================================================
// Matrix Operations
// ============================================================================

// mat3
mat3 mat3_identity(void);
mat3 mat3_add(mat3 a, mat3 b);
mat3 mat3_sub(mat3 a, mat3 b);
mat3 mat3_mul(mat3 a, mat3 b);
mat3 mat3_mul_scalar(mat3 m, float s);
vec3 mat3_mul_vec3(mat3 m, vec3 v);
mat3 mat3_transpose(mat3 m);
float mat3_determinant(mat3 m);
mat3 mat3_inverse(mat3 m);
mat3 mat3_from_euler_angles(vec3 angles); // pitch, yaw, roll
mat3 mat3_from_axis_angle(vec3 axis, float angle);
vec3 mat3_extract_euler_angles(mat3 m);
mat3 mat3_rotation_x(float angle);
mat3 mat3_rotation_y(float angle);
mat3 mat3_rotation_z(float angle);

// mat4
mat4 mat4_identity(void);
mat4 mat4_add(mat4 a, mat4 b);
mat4 mat4_sub(mat4 a, mat4 b);
mat4 mat4_mul(mat4 a, mat4 b);
mat4 mat4_mul_scalar(mat4 m, float s);
vec4 mat4_mul_vec4(mat4 m, vec4 v);
vec3 mat4_mul_vec3(mat4 m, vec3 v, float w);  // w=1 for points, w=0 for vectors
mat4 mat4_transpose(mat4 m);
float mat4_determinant(mat4 m);
mat4 mat4_inverse(mat4 m);

// mat4 construction
mat4 mat4_translation(vec3 v);
mat4 mat4_scale(vec3 v);
mat4 mat4_rotation_x(float angle);
mat4 mat4_rotation_y(float angle);
mat4 mat4_rotation_z(float angle);
mat4 mat4_from_euler_angles(vec3 angles);
mat4 mat4_from_axis_angle(vec3 axis, float angle);
mat4 mat4_rotate(mat4 m, float angle, vec3 axis);
mat4 mat4_translate(mat4 m, vec3 v);
mat4 mat4_scale_by(mat4 m, vec3 v);

// mat4 decomposition
vec3 mat4_extract_euler_angles(mat4 m);
void mat4_extract_axis_angle(mat4 m, vec3 *axis, float *angle);
void mat4_decompose(mat4 m, vec3 *scale, vec3 *rotation, vec3 *translation);

// mat3/mat4 outer product
mat3 mat3_outer_product(vec3 c, vec3 r);
mat4 mat4_outer_product(vec4 c, vec4 r);

// ============================================================================
// Scalar Functions
// ============================================================================

float math_clamp(float val, float min, float max);
float math_lerp(float a, float b, float t);
float math_fract(float x);
float math_trunc(float x);
float math_sign(float x);
float math_radians(float degrees);
float math_degrees(float radians);

// ============================================================================
// Lua Registration
// ============================================================================

void lua_math_register(lua_State *L, int ext_table_index);

#endif // MATH_EXT_H
