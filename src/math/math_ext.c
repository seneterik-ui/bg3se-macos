/**
 * math_ext.c - Ext.Math API Implementation
 *
 * Vector, matrix, and math utilities.
 */

#include "math_ext.h"
#include <math.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// ============================================================================
// vec2 Operations
// ============================================================================

vec2 vec2_add(vec2 a, vec2 b) {
    return (vec2){a.x + b.x, a.y + b.y};
}

vec2 vec2_sub(vec2 a, vec2 b) {
    return (vec2){a.x - b.x, a.y - b.y};
}

vec2 vec2_mul(vec2 a, float s) {
    return (vec2){a.x * s, a.y * s};
}

vec2 vec2_div(vec2 a, float s) {
    if (s == 0.0f) return a;
    return (vec2){a.x / s, a.y / s};
}

float vec2_dot(vec2 a, vec2 b) {
    return a.x * b.x + a.y * b.y;
}

float vec2_length(vec2 v) {
    return sqrtf(v.x * v.x + v.y * v.y);
}

vec2 vec2_normalize(vec2 v) {
    float len = vec2_length(v);
    if (len == 0.0f) return v;
    return vec2_div(v, len);
}

float vec2_distance(vec2 a, vec2 b) {
    return vec2_length(vec2_sub(a, b));
}

float vec2_angle(vec2 a, vec2 b) {
    float d = vec2_dot(a, b);
    float la = vec2_length(a);
    float lb = vec2_length(b);
    if (la == 0.0f || lb == 0.0f) return 0.0f;
    float cos_angle = d / (la * lb);
    // Clamp to [-1, 1] to avoid NaN from acos
    if (cos_angle > 1.0f) cos_angle = 1.0f;
    if (cos_angle < -1.0f) cos_angle = -1.0f;
    return acosf(cos_angle);
}

// ============================================================================
// vec3 Operations
// ============================================================================

vec3 vec3_add(vec3 a, vec3 b) {
    return (vec3){a.x + b.x, a.y + b.y, a.z + b.z};
}

vec3 vec3_sub(vec3 a, vec3 b) {
    return (vec3){a.x - b.x, a.y - b.y, a.z - b.z};
}

vec3 vec3_mul(vec3 a, float s) {
    return (vec3){a.x * s, a.y * s, a.z * s};
}

vec3 vec3_div(vec3 a, float s) {
    if (s == 0.0f) return a;
    return (vec3){a.x / s, a.y / s, a.z / s};
}

float vec3_dot(vec3 a, vec3 b) {
    return a.x * b.x + a.y * b.y + a.z * b.z;
}

vec3 vec3_cross(vec3 a, vec3 b) {
    return (vec3){
        a.y * b.z - a.z * b.y,
        a.z * b.x - a.x * b.z,
        a.x * b.y - a.y * b.x
    };
}

float vec3_length(vec3 v) {
    return sqrtf(v.x * v.x + v.y * v.y + v.z * v.z);
}

vec3 vec3_normalize(vec3 v) {
    float len = vec3_length(v);
    if (len == 0.0f) return v;
    return vec3_div(v, len);
}

float vec3_distance(vec3 a, vec3 b) {
    return vec3_length(vec3_sub(a, b));
}

float vec3_angle(vec3 a, vec3 b) {
    float d = vec3_dot(a, b);
    float la = vec3_length(a);
    float lb = vec3_length(b);
    if (la == 0.0f || lb == 0.0f) return 0.0f;
    float cos_angle = d / (la * lb);
    if (cos_angle > 1.0f) cos_angle = 1.0f;
    if (cos_angle < -1.0f) cos_angle = -1.0f;
    return acosf(cos_angle);
}

vec3 vec3_reflect(vec3 i, vec3 n) {
    // I - 2 * dot(N, I) * N
    float d = vec3_dot(n, i);
    return vec3_sub(i, vec3_mul(n, 2.0f * d));
}

vec3 vec3_project(vec3 v, vec3 normal) {
    // projection of v onto normal
    float d = vec3_dot(v, normal);
    float len_sq = vec3_dot(normal, normal);
    if (len_sq == 0.0f) return (vec3){0, 0, 0};
    return vec3_mul(normal, d / len_sq);
}

vec3 vec3_perpendicular(vec3 v, vec3 normal) {
    // component of v perpendicular to normal
    return vec3_sub(v, vec3_project(v, normal));
}

vec3 vec3_lerp(vec3 a, vec3 b, float t) {
    return (vec3){
        a.x + (b.x - a.x) * t,
        a.y + (b.y - a.y) * t,
        a.z + (b.z - a.z) * t
    };
}

// ============================================================================
// vec4 Operations
// ============================================================================

vec4 vec4_add(vec4 a, vec4 b) {
    return (vec4){a.x + b.x, a.y + b.y, a.z + b.z, a.w + b.w};
}

vec4 vec4_sub(vec4 a, vec4 b) {
    return (vec4){a.x - b.x, a.y - b.y, a.z - b.z, a.w - b.w};
}

vec4 vec4_mul(vec4 a, float s) {
    return (vec4){a.x * s, a.y * s, a.z * s, a.w * s};
}

vec4 vec4_div(vec4 a, float s) {
    if (s == 0.0f) return a;
    return (vec4){a.x / s, a.y / s, a.z / s, a.w / s};
}

float vec4_dot(vec4 a, vec4 b) {
    return a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w;
}

float vec4_length(vec4 v) {
    return sqrtf(v.x * v.x + v.y * v.y + v.z * v.z + v.w * v.w);
}

vec4 vec4_normalize(vec4 v) {
    float len = vec4_length(v);
    if (len == 0.0f) return v;
    return vec4_div(v, len);
}

float vec4_distance(vec4 a, vec4 b) {
    return vec4_length(vec4_sub(a, b));
}

vec4 vec4_lerp(vec4 a, vec4 b, float t) {
    return (vec4){
        a.x + (b.x - a.x) * t,
        a.y + (b.y - a.y) * t,
        a.z + (b.z - a.z) * t,
        a.w + (b.w - a.w) * t
    };
}

// ============================================================================
// mat3 Operations
// ============================================================================

// Column-major indexing helper: mat[col][row] = mat.m[col * 3 + row]
#define MAT3_ELEM(mat, col, row) ((mat).m[(col) * 3 + (row)])

mat3 mat3_identity(void) {
    mat3 m = {0};
    MAT3_ELEM(m, 0, 0) = 1.0f;
    MAT3_ELEM(m, 1, 1) = 1.0f;
    MAT3_ELEM(m, 2, 2) = 1.0f;
    return m;
}

mat3 mat3_add(mat3 a, mat3 b) {
    mat3 r;
    for (int i = 0; i < 9; i++) {
        r.m[i] = a.m[i] + b.m[i];
    }
    return r;
}

mat3 mat3_sub(mat3 a, mat3 b) {
    mat3 r;
    for (int i = 0; i < 9; i++) {
        r.m[i] = a.m[i] - b.m[i];
    }
    return r;
}

mat3 mat3_mul(mat3 a, mat3 b) {
    mat3 r = {0};
    for (int col = 0; col < 3; col++) {
        for (int row = 0; row < 3; row++) {
            float sum = 0.0f;
            for (int k = 0; k < 3; k++) {
                sum += MAT3_ELEM(a, k, row) * MAT3_ELEM(b, col, k);
            }
            MAT3_ELEM(r, col, row) = sum;
        }
    }
    return r;
}

mat3 mat3_mul_scalar(mat3 m, float s) {
    mat3 r;
    for (int i = 0; i < 9; i++) {
        r.m[i] = m.m[i] * s;
    }
    return r;
}

vec3 mat3_mul_vec3(mat3 m, vec3 v) {
    return (vec3){
        MAT3_ELEM(m, 0, 0) * v.x + MAT3_ELEM(m, 1, 0) * v.y + MAT3_ELEM(m, 2, 0) * v.z,
        MAT3_ELEM(m, 0, 1) * v.x + MAT3_ELEM(m, 1, 1) * v.y + MAT3_ELEM(m, 2, 1) * v.z,
        MAT3_ELEM(m, 0, 2) * v.x + MAT3_ELEM(m, 1, 2) * v.y + MAT3_ELEM(m, 2, 2) * v.z
    };
}

mat3 mat3_transpose(mat3 m) {
    mat3 r;
    for (int col = 0; col < 3; col++) {
        for (int row = 0; row < 3; row++) {
            MAT3_ELEM(r, col, row) = MAT3_ELEM(m, row, col);
        }
    }
    return r;
}

float mat3_determinant(mat3 m) {
    return MAT3_ELEM(m, 0, 0) * (MAT3_ELEM(m, 1, 1) * MAT3_ELEM(m, 2, 2) - MAT3_ELEM(m, 2, 1) * MAT3_ELEM(m, 1, 2))
         - MAT3_ELEM(m, 1, 0) * (MAT3_ELEM(m, 0, 1) * MAT3_ELEM(m, 2, 2) - MAT3_ELEM(m, 2, 1) * MAT3_ELEM(m, 0, 2))
         + MAT3_ELEM(m, 2, 0) * (MAT3_ELEM(m, 0, 1) * MAT3_ELEM(m, 1, 2) - MAT3_ELEM(m, 1, 1) * MAT3_ELEM(m, 0, 2));
}

mat3 mat3_inverse(mat3 m) {
    float det = mat3_determinant(m);
    if (fabsf(det) < 1e-10f) {
        return mat3_identity();
    }

    float inv_det = 1.0f / det;
    mat3 r;

    MAT3_ELEM(r, 0, 0) = (MAT3_ELEM(m, 1, 1) * MAT3_ELEM(m, 2, 2) - MAT3_ELEM(m, 2, 1) * MAT3_ELEM(m, 1, 2)) * inv_det;
    MAT3_ELEM(r, 0, 1) = (MAT3_ELEM(m, 0, 2) * MAT3_ELEM(m, 2, 1) - MAT3_ELEM(m, 0, 1) * MAT3_ELEM(m, 2, 2)) * inv_det;
    MAT3_ELEM(r, 0, 2) = (MAT3_ELEM(m, 0, 1) * MAT3_ELEM(m, 1, 2) - MAT3_ELEM(m, 0, 2) * MAT3_ELEM(m, 1, 1)) * inv_det;
    MAT3_ELEM(r, 1, 0) = (MAT3_ELEM(m, 1, 2) * MAT3_ELEM(m, 2, 0) - MAT3_ELEM(m, 1, 0) * MAT3_ELEM(m, 2, 2)) * inv_det;
    MAT3_ELEM(r, 1, 1) = (MAT3_ELEM(m, 0, 0) * MAT3_ELEM(m, 2, 2) - MAT3_ELEM(m, 0, 2) * MAT3_ELEM(m, 2, 0)) * inv_det;
    MAT3_ELEM(r, 1, 2) = (MAT3_ELEM(m, 1, 0) * MAT3_ELEM(m, 0, 2) - MAT3_ELEM(m, 0, 0) * MAT3_ELEM(m, 1, 2)) * inv_det;
    MAT3_ELEM(r, 2, 0) = (MAT3_ELEM(m, 1, 0) * MAT3_ELEM(m, 2, 1) - MAT3_ELEM(m, 2, 0) * MAT3_ELEM(m, 1, 1)) * inv_det;
    MAT3_ELEM(r, 2, 1) = (MAT3_ELEM(m, 2, 0) * MAT3_ELEM(m, 0, 1) - MAT3_ELEM(m, 0, 0) * MAT3_ELEM(m, 2, 1)) * inv_det;
    MAT3_ELEM(r, 2, 2) = (MAT3_ELEM(m, 0, 0) * MAT3_ELEM(m, 1, 1) - MAT3_ELEM(m, 1, 0) * MAT3_ELEM(m, 0, 1)) * inv_det;

    return r;
}

mat3 mat3_rotation_x(float angle) {
    mat3 r = mat3_identity();
    float c = cosf(angle);
    float s = sinf(angle);
    MAT3_ELEM(r, 1, 1) = c;
    MAT3_ELEM(r, 1, 2) = s;
    MAT3_ELEM(r, 2, 1) = -s;
    MAT3_ELEM(r, 2, 2) = c;
    return r;
}

mat3 mat3_rotation_y(float angle) {
    mat3 r = mat3_identity();
    float c = cosf(angle);
    float s = sinf(angle);
    MAT3_ELEM(r, 0, 0) = c;
    MAT3_ELEM(r, 0, 2) = -s;
    MAT3_ELEM(r, 2, 0) = s;
    MAT3_ELEM(r, 2, 2) = c;
    return r;
}

mat3 mat3_rotation_z(float angle) {
    mat3 r = mat3_identity();
    float c = cosf(angle);
    float s = sinf(angle);
    MAT3_ELEM(r, 0, 0) = c;
    MAT3_ELEM(r, 0, 1) = s;
    MAT3_ELEM(r, 1, 0) = -s;
    MAT3_ELEM(r, 1, 1) = c;
    return r;
}

mat3 mat3_from_euler_angles(vec3 angles) {
    // angles = (pitch, yaw, roll) in radians
    mat3 rx = mat3_rotation_x(angles.x);
    mat3 ry = mat3_rotation_y(angles.y);
    mat3 rz = mat3_rotation_z(angles.z);
    return mat3_mul(mat3_mul(rz, ry), rx);
}

mat3 mat3_from_axis_angle(vec3 axis, float angle) {
    axis = vec3_normalize(axis);
    float c = cosf(angle);
    float s = sinf(angle);
    float t = 1.0f - c;

    mat3 r;
    MAT3_ELEM(r, 0, 0) = t * axis.x * axis.x + c;
    MAT3_ELEM(r, 0, 1) = t * axis.x * axis.y + s * axis.z;
    MAT3_ELEM(r, 0, 2) = t * axis.x * axis.z - s * axis.y;
    MAT3_ELEM(r, 1, 0) = t * axis.x * axis.y - s * axis.z;
    MAT3_ELEM(r, 1, 1) = t * axis.y * axis.y + c;
    MAT3_ELEM(r, 1, 2) = t * axis.y * axis.z + s * axis.x;
    MAT3_ELEM(r, 2, 0) = t * axis.x * axis.z + s * axis.y;
    MAT3_ELEM(r, 2, 1) = t * axis.y * axis.z - s * axis.x;
    MAT3_ELEM(r, 2, 2) = t * axis.z * axis.z + c;

    return r;
}

vec3 mat3_extract_euler_angles(mat3 m) {
    vec3 angles;

    // Extract pitch (rotation around X)
    float sp = -MAT3_ELEM(m, 0, 2);
    if (sp <= -1.0f) {
        angles.x = -M_PI / 2.0f;
    } else if (sp >= 1.0f) {
        angles.x = M_PI / 2.0f;
    } else {
        angles.x = asinf(sp);
    }

    // Check for gimbal lock
    if (fabsf(sp) > 0.9999f) {
        angles.y = 0.0f;
        angles.z = atan2f(-MAT3_ELEM(m, 1, 0), MAT3_ELEM(m, 1, 1));
    } else {
        angles.y = atan2f(MAT3_ELEM(m, 0, 1), MAT3_ELEM(m, 0, 0));
        angles.z = atan2f(MAT3_ELEM(m, 1, 2), MAT3_ELEM(m, 2, 2));
    }

    return angles;
}

mat3 mat3_outer_product(vec3 c, vec3 r) {
    mat3 m;
    MAT3_ELEM(m, 0, 0) = c.x * r.x; MAT3_ELEM(m, 1, 0) = c.x * r.y; MAT3_ELEM(m, 2, 0) = c.x * r.z;
    MAT3_ELEM(m, 0, 1) = c.y * r.x; MAT3_ELEM(m, 1, 1) = c.y * r.y; MAT3_ELEM(m, 2, 1) = c.y * r.z;
    MAT3_ELEM(m, 0, 2) = c.z * r.x; MAT3_ELEM(m, 1, 2) = c.z * r.y; MAT3_ELEM(m, 2, 2) = c.z * r.z;
    return m;
}

// ============================================================================
// mat4 Operations
// ============================================================================

// Column-major indexing helper: mat[col][row] = mat.m[col * 4 + row]
#define MAT4_ELEM(mat, col, row) ((mat).m[(col) * 4 + (row)])

mat4 mat4_identity(void) {
    mat4 m = {0};
    MAT4_ELEM(m, 0, 0) = 1.0f;
    MAT4_ELEM(m, 1, 1) = 1.0f;
    MAT4_ELEM(m, 2, 2) = 1.0f;
    MAT4_ELEM(m, 3, 3) = 1.0f;
    return m;
}

mat4 mat4_add(mat4 a, mat4 b) {
    mat4 r;
    for (int i = 0; i < 16; i++) {
        r.m[i] = a.m[i] + b.m[i];
    }
    return r;
}

mat4 mat4_sub(mat4 a, mat4 b) {
    mat4 r;
    for (int i = 0; i < 16; i++) {
        r.m[i] = a.m[i] - b.m[i];
    }
    return r;
}

mat4 mat4_mul(mat4 a, mat4 b) {
    mat4 r = {0};
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            float sum = 0.0f;
            for (int k = 0; k < 4; k++) {
                sum += MAT4_ELEM(a, k, row) * MAT4_ELEM(b, col, k);
            }
            MAT4_ELEM(r, col, row) = sum;
        }
    }
    return r;
}

mat4 mat4_mul_scalar(mat4 m, float s) {
    mat4 r;
    for (int i = 0; i < 16; i++) {
        r.m[i] = m.m[i] * s;
    }
    return r;
}

vec4 mat4_mul_vec4(mat4 m, vec4 v) {
    return (vec4){
        MAT4_ELEM(m, 0, 0) * v.x + MAT4_ELEM(m, 1, 0) * v.y + MAT4_ELEM(m, 2, 0) * v.z + MAT4_ELEM(m, 3, 0) * v.w,
        MAT4_ELEM(m, 0, 1) * v.x + MAT4_ELEM(m, 1, 1) * v.y + MAT4_ELEM(m, 2, 1) * v.z + MAT4_ELEM(m, 3, 1) * v.w,
        MAT4_ELEM(m, 0, 2) * v.x + MAT4_ELEM(m, 1, 2) * v.y + MAT4_ELEM(m, 2, 2) * v.z + MAT4_ELEM(m, 3, 2) * v.w,
        MAT4_ELEM(m, 0, 3) * v.x + MAT4_ELEM(m, 1, 3) * v.y + MAT4_ELEM(m, 2, 3) * v.z + MAT4_ELEM(m, 3, 3) * v.w
    };
}

vec3 mat4_mul_vec3(mat4 m, vec3 v, float w) {
    vec4 v4 = mat4_mul_vec4(m, (vec4){v.x, v.y, v.z, w});
    return (vec3){v4.x, v4.y, v4.z};
}

mat4 mat4_transpose(mat4 m) {
    mat4 r;
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            MAT4_ELEM(r, col, row) = MAT4_ELEM(m, row, col);
        }
    }
    return r;
}

float mat4_determinant(mat4 m) {
    float s0 = MAT4_ELEM(m, 0, 0) * MAT4_ELEM(m, 1, 1) - MAT4_ELEM(m, 1, 0) * MAT4_ELEM(m, 0, 1);
    float s1 = MAT4_ELEM(m, 0, 0) * MAT4_ELEM(m, 2, 1) - MAT4_ELEM(m, 2, 0) * MAT4_ELEM(m, 0, 1);
    float s2 = MAT4_ELEM(m, 0, 0) * MAT4_ELEM(m, 3, 1) - MAT4_ELEM(m, 3, 0) * MAT4_ELEM(m, 0, 1);
    float s3 = MAT4_ELEM(m, 1, 0) * MAT4_ELEM(m, 2, 1) - MAT4_ELEM(m, 2, 0) * MAT4_ELEM(m, 1, 1);
    float s4 = MAT4_ELEM(m, 1, 0) * MAT4_ELEM(m, 3, 1) - MAT4_ELEM(m, 3, 0) * MAT4_ELEM(m, 1, 1);
    float s5 = MAT4_ELEM(m, 2, 0) * MAT4_ELEM(m, 3, 1) - MAT4_ELEM(m, 3, 0) * MAT4_ELEM(m, 2, 1);

    float c5 = MAT4_ELEM(m, 2, 2) * MAT4_ELEM(m, 3, 3) - MAT4_ELEM(m, 3, 2) * MAT4_ELEM(m, 2, 3);
    float c4 = MAT4_ELEM(m, 1, 2) * MAT4_ELEM(m, 3, 3) - MAT4_ELEM(m, 3, 2) * MAT4_ELEM(m, 1, 3);
    float c3 = MAT4_ELEM(m, 1, 2) * MAT4_ELEM(m, 2, 3) - MAT4_ELEM(m, 2, 2) * MAT4_ELEM(m, 1, 3);
    float c2 = MAT4_ELEM(m, 0, 2) * MAT4_ELEM(m, 3, 3) - MAT4_ELEM(m, 3, 2) * MAT4_ELEM(m, 0, 3);
    float c1 = MAT4_ELEM(m, 0, 2) * MAT4_ELEM(m, 2, 3) - MAT4_ELEM(m, 2, 2) * MAT4_ELEM(m, 0, 3);
    float c0 = MAT4_ELEM(m, 0, 2) * MAT4_ELEM(m, 1, 3) - MAT4_ELEM(m, 1, 2) * MAT4_ELEM(m, 0, 3);

    return s0 * c5 - s1 * c4 + s2 * c3 + s3 * c2 - s4 * c1 + s5 * c0;
}

mat4 mat4_inverse(mat4 m) {
    float s0 = MAT4_ELEM(m, 0, 0) * MAT4_ELEM(m, 1, 1) - MAT4_ELEM(m, 1, 0) * MAT4_ELEM(m, 0, 1);
    float s1 = MAT4_ELEM(m, 0, 0) * MAT4_ELEM(m, 2, 1) - MAT4_ELEM(m, 2, 0) * MAT4_ELEM(m, 0, 1);
    float s2 = MAT4_ELEM(m, 0, 0) * MAT4_ELEM(m, 3, 1) - MAT4_ELEM(m, 3, 0) * MAT4_ELEM(m, 0, 1);
    float s3 = MAT4_ELEM(m, 1, 0) * MAT4_ELEM(m, 2, 1) - MAT4_ELEM(m, 2, 0) * MAT4_ELEM(m, 1, 1);
    float s4 = MAT4_ELEM(m, 1, 0) * MAT4_ELEM(m, 3, 1) - MAT4_ELEM(m, 3, 0) * MAT4_ELEM(m, 1, 1);
    float s5 = MAT4_ELEM(m, 2, 0) * MAT4_ELEM(m, 3, 1) - MAT4_ELEM(m, 3, 0) * MAT4_ELEM(m, 2, 1);

    float c5 = MAT4_ELEM(m, 2, 2) * MAT4_ELEM(m, 3, 3) - MAT4_ELEM(m, 3, 2) * MAT4_ELEM(m, 2, 3);
    float c4 = MAT4_ELEM(m, 1, 2) * MAT4_ELEM(m, 3, 3) - MAT4_ELEM(m, 3, 2) * MAT4_ELEM(m, 1, 3);
    float c3 = MAT4_ELEM(m, 1, 2) * MAT4_ELEM(m, 2, 3) - MAT4_ELEM(m, 2, 2) * MAT4_ELEM(m, 1, 3);
    float c2 = MAT4_ELEM(m, 0, 2) * MAT4_ELEM(m, 3, 3) - MAT4_ELEM(m, 3, 2) * MAT4_ELEM(m, 0, 3);
    float c1 = MAT4_ELEM(m, 0, 2) * MAT4_ELEM(m, 2, 3) - MAT4_ELEM(m, 2, 2) * MAT4_ELEM(m, 0, 3);
    float c0 = MAT4_ELEM(m, 0, 2) * MAT4_ELEM(m, 1, 3) - MAT4_ELEM(m, 1, 2) * MAT4_ELEM(m, 0, 3);

    float det = s0 * c5 - s1 * c4 + s2 * c3 + s3 * c2 - s4 * c1 + s5 * c0;
    if (fabsf(det) < 1e-10f) {
        return mat4_identity();
    }

    float inv_det = 1.0f / det;
    mat4 r;

    MAT4_ELEM(r, 0, 0) = ( MAT4_ELEM(m, 1, 1) * c5 - MAT4_ELEM(m, 2, 1) * c4 + MAT4_ELEM(m, 3, 1) * c3) * inv_det;
    MAT4_ELEM(r, 0, 1) = (-MAT4_ELEM(m, 0, 1) * c5 + MAT4_ELEM(m, 2, 1) * c2 - MAT4_ELEM(m, 3, 1) * c1) * inv_det;
    MAT4_ELEM(r, 0, 2) = ( MAT4_ELEM(m, 0, 1) * c4 - MAT4_ELEM(m, 1, 1) * c2 + MAT4_ELEM(m, 3, 1) * c0) * inv_det;
    MAT4_ELEM(r, 0, 3) = (-MAT4_ELEM(m, 0, 1) * c3 + MAT4_ELEM(m, 1, 1) * c1 - MAT4_ELEM(m, 2, 1) * c0) * inv_det;

    MAT4_ELEM(r, 1, 0) = (-MAT4_ELEM(m, 1, 0) * c5 + MAT4_ELEM(m, 2, 0) * c4 - MAT4_ELEM(m, 3, 0) * c3) * inv_det;
    MAT4_ELEM(r, 1, 1) = ( MAT4_ELEM(m, 0, 0) * c5 - MAT4_ELEM(m, 2, 0) * c2 + MAT4_ELEM(m, 3, 0) * c1) * inv_det;
    MAT4_ELEM(r, 1, 2) = (-MAT4_ELEM(m, 0, 0) * c4 + MAT4_ELEM(m, 1, 0) * c2 - MAT4_ELEM(m, 3, 0) * c0) * inv_det;
    MAT4_ELEM(r, 1, 3) = ( MAT4_ELEM(m, 0, 0) * c3 - MAT4_ELEM(m, 1, 0) * c1 + MAT4_ELEM(m, 2, 0) * c0) * inv_det;

    MAT4_ELEM(r, 2, 0) = ( MAT4_ELEM(m, 1, 3) * s5 - MAT4_ELEM(m, 2, 3) * s4 + MAT4_ELEM(m, 3, 3) * s3) * inv_det;
    MAT4_ELEM(r, 2, 1) = (-MAT4_ELEM(m, 0, 3) * s5 + MAT4_ELEM(m, 2, 3) * s2 - MAT4_ELEM(m, 3, 3) * s1) * inv_det;
    MAT4_ELEM(r, 2, 2) = ( MAT4_ELEM(m, 0, 3) * s4 - MAT4_ELEM(m, 1, 3) * s2 + MAT4_ELEM(m, 3, 3) * s0) * inv_det;
    MAT4_ELEM(r, 2, 3) = (-MAT4_ELEM(m, 0, 3) * s3 + MAT4_ELEM(m, 1, 3) * s1 - MAT4_ELEM(m, 2, 3) * s0) * inv_det;

    MAT4_ELEM(r, 3, 0) = (-MAT4_ELEM(m, 1, 2) * s5 + MAT4_ELEM(m, 2, 2) * s4 - MAT4_ELEM(m, 3, 2) * s3) * inv_det;
    MAT4_ELEM(r, 3, 1) = ( MAT4_ELEM(m, 0, 2) * s5 - MAT4_ELEM(m, 2, 2) * s2 + MAT4_ELEM(m, 3, 2) * s1) * inv_det;
    MAT4_ELEM(r, 3, 2) = (-MAT4_ELEM(m, 0, 2) * s4 + MAT4_ELEM(m, 1, 2) * s2 - MAT4_ELEM(m, 3, 2) * s0) * inv_det;
    MAT4_ELEM(r, 3, 3) = ( MAT4_ELEM(m, 0, 2) * s3 - MAT4_ELEM(m, 1, 2) * s1 + MAT4_ELEM(m, 2, 2) * s0) * inv_det;

    return r;
}

mat4 mat4_translation(vec3 v) {
    mat4 m = mat4_identity();
    MAT4_ELEM(m, 3, 0) = v.x;
    MAT4_ELEM(m, 3, 1) = v.y;
    MAT4_ELEM(m, 3, 2) = v.z;
    return m;
}

mat4 mat4_scale(vec3 v) {
    mat4 m = mat4_identity();
    MAT4_ELEM(m, 0, 0) = v.x;
    MAT4_ELEM(m, 1, 1) = v.y;
    MAT4_ELEM(m, 2, 2) = v.z;
    return m;
}

mat4 mat4_rotation_x(float angle) {
    mat4 r = mat4_identity();
    float c = cosf(angle);
    float s = sinf(angle);
    MAT4_ELEM(r, 1, 1) = c;
    MAT4_ELEM(r, 1, 2) = s;
    MAT4_ELEM(r, 2, 1) = -s;
    MAT4_ELEM(r, 2, 2) = c;
    return r;
}

mat4 mat4_rotation_y(float angle) {
    mat4 r = mat4_identity();
    float c = cosf(angle);
    float s = sinf(angle);
    MAT4_ELEM(r, 0, 0) = c;
    MAT4_ELEM(r, 0, 2) = -s;
    MAT4_ELEM(r, 2, 0) = s;
    MAT4_ELEM(r, 2, 2) = c;
    return r;
}

mat4 mat4_rotation_z(float angle) {
    mat4 r = mat4_identity();
    float c = cosf(angle);
    float s = sinf(angle);
    MAT4_ELEM(r, 0, 0) = c;
    MAT4_ELEM(r, 0, 1) = s;
    MAT4_ELEM(r, 1, 0) = -s;
    MAT4_ELEM(r, 1, 1) = c;
    return r;
}

mat4 mat4_from_euler_angles(vec3 angles) {
    mat4 rx = mat4_rotation_x(angles.x);
    mat4 ry = mat4_rotation_y(angles.y);
    mat4 rz = mat4_rotation_z(angles.z);
    return mat4_mul(mat4_mul(rz, ry), rx);
}

mat4 mat4_from_axis_angle(vec3 axis, float angle) {
    axis = vec3_normalize(axis);
    float c = cosf(angle);
    float s = sinf(angle);
    float t = 1.0f - c;

    mat4 r = mat4_identity();
    MAT4_ELEM(r, 0, 0) = t * axis.x * axis.x + c;
    MAT4_ELEM(r, 0, 1) = t * axis.x * axis.y + s * axis.z;
    MAT4_ELEM(r, 0, 2) = t * axis.x * axis.z - s * axis.y;
    MAT4_ELEM(r, 1, 0) = t * axis.x * axis.y - s * axis.z;
    MAT4_ELEM(r, 1, 1) = t * axis.y * axis.y + c;
    MAT4_ELEM(r, 1, 2) = t * axis.y * axis.z + s * axis.x;
    MAT4_ELEM(r, 2, 0) = t * axis.x * axis.z + s * axis.y;
    MAT4_ELEM(r, 2, 1) = t * axis.y * axis.z - s * axis.x;
    MAT4_ELEM(r, 2, 2) = t * axis.z * axis.z + c;

    return r;
}

mat4 mat4_rotate(mat4 m, float angle, vec3 axis) {
    mat4 rot = mat4_from_axis_angle(axis, angle);
    return mat4_mul(m, rot);
}

mat4 mat4_translate(mat4 m, vec3 v) {
    mat4 t = mat4_translation(v);
    return mat4_mul(m, t);
}

mat4 mat4_scale_by(mat4 m, vec3 v) {
    mat4 s = mat4_scale(v);
    return mat4_mul(m, s);
}

vec3 mat4_extract_euler_angles(mat4 m) {
    vec3 angles;

    float sp = -MAT4_ELEM(m, 0, 2);
    if (sp <= -1.0f) {
        angles.x = -M_PI / 2.0f;
    } else if (sp >= 1.0f) {
        angles.x = M_PI / 2.0f;
    } else {
        angles.x = asinf(sp);
    }

    if (fabsf(sp) > 0.9999f) {
        angles.y = 0.0f;
        angles.z = atan2f(-MAT4_ELEM(m, 1, 0), MAT4_ELEM(m, 1, 1));
    } else {
        angles.y = atan2f(MAT4_ELEM(m, 0, 1), MAT4_ELEM(m, 0, 0));
        angles.z = atan2f(MAT4_ELEM(m, 1, 2), MAT4_ELEM(m, 2, 2));
    }

    return angles;
}

void mat4_extract_axis_angle(mat4 m, vec3 *axis, float *angle) {
    float trace = MAT4_ELEM(m, 0, 0) + MAT4_ELEM(m, 1, 1) + MAT4_ELEM(m, 2, 2);
    float cos_angle = (trace - 1.0f) / 2.0f;

    if (cos_angle > 1.0f) cos_angle = 1.0f;
    if (cos_angle < -1.0f) cos_angle = -1.0f;

    *angle = acosf(cos_angle);

    if (fabsf(*angle) < 1e-6f) {
        *axis = (vec3){1, 0, 0};
    } else {
        float s = 1.0f / (2.0f * sinf(*angle));
        axis->x = (MAT4_ELEM(m, 1, 2) - MAT4_ELEM(m, 2, 1)) * s;
        axis->y = (MAT4_ELEM(m, 2, 0) - MAT4_ELEM(m, 0, 2)) * s;
        axis->z = (MAT4_ELEM(m, 0, 1) - MAT4_ELEM(m, 1, 0)) * s;
    }
}

void mat4_decompose(mat4 m, vec3 *scale, vec3 *rotation, vec3 *translation) {
    // Extract translation
    translation->x = MAT4_ELEM(m, 3, 0);
    translation->y = MAT4_ELEM(m, 3, 1);
    translation->z = MAT4_ELEM(m, 3, 2);

    // Extract scale
    vec3 col0 = {MAT4_ELEM(m, 0, 0), MAT4_ELEM(m, 0, 1), MAT4_ELEM(m, 0, 2)};
    vec3 col1 = {MAT4_ELEM(m, 1, 0), MAT4_ELEM(m, 1, 1), MAT4_ELEM(m, 1, 2)};
    vec3 col2 = {MAT4_ELEM(m, 2, 0), MAT4_ELEM(m, 2, 1), MAT4_ELEM(m, 2, 2)};

    scale->x = vec3_length(col0);
    scale->y = vec3_length(col1);
    scale->z = vec3_length(col2);

    // Handle negative scale (determinant check)
    mat3 rot3;
    for (int i = 0; i < 3; i++) {
        MAT3_ELEM(rot3, i, 0) = MAT4_ELEM(m, i, 0) / (scale->x != 0 ? scale->x : 1.0f);
        MAT3_ELEM(rot3, i, 1) = MAT4_ELEM(m, i, 1) / (scale->y != 0 ? scale->y : 1.0f);
        MAT3_ELEM(rot3, i, 2) = MAT4_ELEM(m, i, 2) / (scale->z != 0 ? scale->z : 1.0f);
    }

    if (mat3_determinant(rot3) < 0) {
        scale->x = -scale->x;
        for (int i = 0; i < 3; i++) {
            MAT3_ELEM(rot3, 0, i) = -MAT3_ELEM(rot3, 0, i);
        }
    }

    // Extract rotation as euler angles
    *rotation = mat3_extract_euler_angles(rot3);
}

mat4 mat4_outer_product(vec4 c, vec4 r) {
    mat4 m;
    MAT4_ELEM(m, 0, 0) = c.x * r.x; MAT4_ELEM(m, 1, 0) = c.x * r.y; MAT4_ELEM(m, 2, 0) = c.x * r.z; MAT4_ELEM(m, 3, 0) = c.x * r.w;
    MAT4_ELEM(m, 0, 1) = c.y * r.x; MAT4_ELEM(m, 1, 1) = c.y * r.y; MAT4_ELEM(m, 2, 1) = c.y * r.z; MAT4_ELEM(m, 3, 1) = c.y * r.w;
    MAT4_ELEM(m, 0, 2) = c.z * r.x; MAT4_ELEM(m, 1, 2) = c.z * r.y; MAT4_ELEM(m, 2, 2) = c.z * r.z; MAT4_ELEM(m, 3, 2) = c.z * r.w;
    MAT4_ELEM(m, 0, 3) = c.w * r.x; MAT4_ELEM(m, 1, 3) = c.w * r.y; MAT4_ELEM(m, 2, 3) = c.w * r.z; MAT4_ELEM(m, 3, 3) = c.w * r.w;
    return m;
}

// ============================================================================
// Scalar Functions
// ============================================================================

float math_clamp(float val, float min, float max) {
    if (val < min) return min;
    if (val > max) return max;
    return val;
}

float math_lerp(float a, float b, float t) {
    return a + (b - a) * t;
}

float math_fract(float x) {
    return x - floorf(x);
}

float math_trunc(float x) {
    return truncf(x);
}

float math_sign(float x) {
    if (x > 0.0f) return 1.0f;
    if (x < 0.0f) return -1.0f;
    return 0.0f;
}

float math_radians(float degrees) {
    return degrees * (M_PI / 180.0f);
}

float math_degrees(float radians) {
    return radians * (180.0f / M_PI);
}
