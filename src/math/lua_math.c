/**
 * lua_math.c - Ext.Math Lua Bindings
 *
 * Provides Lua access to vector/matrix math operations.
 */

#include "math_ext.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <math.h>

// ============================================================================
// Helper: Parse vector from table or number arguments
// ============================================================================

static bool parse_vec3_from_table(lua_State *L, int idx, vec3 *out) {
    if (!lua_istable(L, idx)) return false;

    lua_rawgeti(L, idx, 1);
    out->x = lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 2);
    out->y = lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 3);
    out->z = lua_tonumber(L, -1);
    lua_pop(L, 1);

    return true;
}

static bool parse_vec4_from_table(lua_State *L, int idx, vec4 *out) {
    if (!lua_istable(L, idx)) return false;

    lua_rawgeti(L, idx, 1);
    out->x = lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 2);
    out->y = lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 3);
    out->z = lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 4);
    out->w = lua_tonumber(L, -1);
    lua_pop(L, 1);

    return true;
}

static bool parse_mat3_from_table(lua_State *L, int idx, mat3 *out) {
    if (!lua_istable(L, idx)) return false;

    for (int i = 0; i < 9; i++) {
        lua_rawgeti(L, idx, i + 1);
        out->m[i] = lua_tonumber(L, -1);
        lua_pop(L, 1);
    }
    return true;
}

static bool parse_mat4_from_table(lua_State *L, int idx, mat4 *out) {
    if (!lua_istable(L, idx)) return false;

    for (int i = 0; i < 16; i++) {
        lua_rawgeti(L, idx, i + 1);
        out->m[i] = lua_tonumber(L, -1);
        lua_pop(L, 1);
    }
    return true;
}

static void push_vec3(lua_State *L, vec3 v) {
    lua_createtable(L, 3, 0);
    lua_pushnumber(L, v.x);
    lua_rawseti(L, -2, 1);
    lua_pushnumber(L, v.y);
    lua_rawseti(L, -2, 2);
    lua_pushnumber(L, v.z);
    lua_rawseti(L, -2, 3);
}

static void push_vec4(lua_State *L, vec4 v) {
    lua_createtable(L, 4, 0);
    lua_pushnumber(L, v.x);
    lua_rawseti(L, -2, 1);
    lua_pushnumber(L, v.y);
    lua_rawseti(L, -2, 2);
    lua_pushnumber(L, v.z);
    lua_rawseti(L, -2, 3);
    lua_pushnumber(L, v.w);
    lua_rawseti(L, -2, 4);
}

static void push_mat3(lua_State *L, mat3 m) {
    lua_createtable(L, 9, 0);
    for (int i = 0; i < 9; i++) {
        lua_pushnumber(L, m.m[i]);
        lua_rawseti(L, -2, i + 1);
    }
}

static void push_mat4(lua_State *L, mat4 m) {
    lua_createtable(L, 16, 0);
    for (int i = 0; i < 16; i++) {
        lua_pushnumber(L, m.m[i]);
        lua_rawseti(L, -2, i + 1);
    }
}

// Detect vector dimension from table size
static int get_vec_size(lua_State *L, int idx) {
    if (!lua_istable(L, idx)) return 0;
    return (int)lua_rawlen(L, idx);
}

// ============================================================================
// Ext.Math.Add(a, b)
// ============================================================================

static int lua_math_add(lua_State *L) {
    int size_a = get_vec_size(L, 1);
    int size_b = get_vec_size(L, 2);

    if (size_a == 3 && size_b == 3) {
        vec3 a, b;
        parse_vec3_from_table(L, 1, &a);
        parse_vec3_from_table(L, 2, &b);
        push_vec3(L, vec3_add(a, b));
        return 1;
    } else if (size_a == 4 && size_b == 4) {
        vec4 a, b;
        parse_vec4_from_table(L, 1, &a);
        parse_vec4_from_table(L, 2, &b);
        push_vec4(L, vec4_add(a, b));
        return 1;
    } else if (size_a == 9 && size_b == 9) {
        mat3 a, b;
        parse_mat3_from_table(L, 1, &a);
        parse_mat3_from_table(L, 2, &b);
        push_mat3(L, mat3_add(a, b));
        return 1;
    } else if (size_a == 16 && size_b == 16) {
        mat4 a, b;
        parse_mat4_from_table(L, 1, &a);
        parse_mat4_from_table(L, 2, &b);
        push_mat4(L, mat4_add(a, b));
        return 1;
    }

    return luaL_error(L, "Add requires two vectors or matrices of the same size");
}

// ============================================================================
// Ext.Math.Sub(a, b)
// ============================================================================

static int lua_math_sub(lua_State *L) {
    int size_a = get_vec_size(L, 1);
    int size_b = get_vec_size(L, 2);

    if (size_a == 3 && size_b == 3) {
        vec3 a, b;
        parse_vec3_from_table(L, 1, &a);
        parse_vec3_from_table(L, 2, &b);
        push_vec3(L, vec3_sub(a, b));
        return 1;
    } else if (size_a == 4 && size_b == 4) {
        vec4 a, b;
        parse_vec4_from_table(L, 1, &a);
        parse_vec4_from_table(L, 2, &b);
        push_vec4(L, vec4_sub(a, b));
        return 1;
    } else if (size_a == 9 && size_b == 9) {
        mat3 a, b;
        parse_mat3_from_table(L, 1, &a);
        parse_mat3_from_table(L, 2, &b);
        push_mat3(L, mat3_sub(a, b));
        return 1;
    } else if (size_a == 16 && size_b == 16) {
        mat4 a, b;
        parse_mat4_from_table(L, 1, &a);
        parse_mat4_from_table(L, 2, &b);
        push_mat4(L, mat4_sub(a, b));
        return 1;
    }

    return luaL_error(L, "Sub requires two vectors or matrices of the same size");
}

// ============================================================================
// Ext.Math.Mul(a, b) - vector*scalar, matrix*matrix, matrix*vector
// ============================================================================

static int lua_math_mul(lua_State *L) {
    int size_a = get_vec_size(L, 1);

    // Vector * scalar
    if (size_a == 3 && lua_isnumber(L, 2)) {
        vec3 a;
        parse_vec3_from_table(L, 1, &a);
        float s = lua_tonumber(L, 2);
        push_vec3(L, vec3_mul(a, s));
        return 1;
    }
    if (size_a == 4 && lua_isnumber(L, 2)) {
        vec4 a;
        parse_vec4_from_table(L, 1, &a);
        float s = lua_tonumber(L, 2);
        push_vec4(L, vec4_mul(a, s));
        return 1;
    }

    int size_b = get_vec_size(L, 2);

    // mat3 * mat3
    if (size_a == 9 && size_b == 9) {
        mat3 a, b;
        parse_mat3_from_table(L, 1, &a);
        parse_mat3_from_table(L, 2, &b);
        push_mat3(L, mat3_mul(a, b));
        return 1;
    }

    // mat4 * mat4
    if (size_a == 16 && size_b == 16) {
        mat4 a, b;
        parse_mat4_from_table(L, 1, &a);
        parse_mat4_from_table(L, 2, &b);
        push_mat4(L, mat4_mul(a, b));
        return 1;
    }

    // mat3 * vec3
    if (size_a == 9 && size_b == 3) {
        mat3 m;
        vec3 v;
        parse_mat3_from_table(L, 1, &m);
        parse_vec3_from_table(L, 2, &v);
        push_vec3(L, mat3_mul_vec3(m, v));
        return 1;
    }

    // mat4 * vec4
    if (size_a == 16 && size_b == 4) {
        mat4 m;
        vec4 v;
        parse_mat4_from_table(L, 1, &m);
        parse_vec4_from_table(L, 2, &v);
        push_vec4(L, mat4_mul_vec4(m, v));
        return 1;
    }

    // mat * scalar
    if (size_a == 9 && lua_isnumber(L, 2)) {
        mat3 m;
        parse_mat3_from_table(L, 1, &m);
        float s = lua_tonumber(L, 2);
        push_mat3(L, mat3_mul_scalar(m, s));
        return 1;
    }
    if (size_a == 16 && lua_isnumber(L, 2)) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        float s = lua_tonumber(L, 2);
        push_mat4(L, mat4_mul_scalar(m, s));
        return 1;
    }

    return luaL_error(L, "Mul: unsupported operand types");
}

// ============================================================================
// Ext.Math.Div(a, b) - vector / scalar
// ============================================================================

static int lua_math_div(lua_State *L) {
    int size_a = get_vec_size(L, 1);

    if (size_a == 3 && lua_isnumber(L, 2)) {
        vec3 a;
        parse_vec3_from_table(L, 1, &a);
        float s = lua_tonumber(L, 2);
        push_vec3(L, vec3_div(a, s));
        return 1;
    }
    if (size_a == 4 && lua_isnumber(L, 2)) {
        vec4 a;
        parse_vec4_from_table(L, 1, &a);
        float s = lua_tonumber(L, 2);
        push_vec4(L, vec4_div(a, s));
        return 1;
    }

    return luaL_error(L, "Div requires a vector and a scalar");
}

// ============================================================================
// Ext.Math.Normalize(x)
// ============================================================================

static int lua_math_normalize(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 3) {
        vec3 v;
        parse_vec3_from_table(L, 1, &v);
        push_vec3(L, vec3_normalize(v));
        return 1;
    } else if (size == 4) {
        vec4 v;
        parse_vec4_from_table(L, 1, &v);
        push_vec4(L, vec4_normalize(v));
        return 1;
    }

    return luaL_error(L, "Normalize requires a vec3 or vec4");
}

// ============================================================================
// Ext.Math.Cross(x, y) - vec3 only
// ============================================================================

static int lua_math_cross(lua_State *L) {
    vec3 a, b;
    if (!parse_vec3_from_table(L, 1, &a) || !parse_vec3_from_table(L, 2, &b)) {
        return luaL_error(L, "Cross requires two vec3");
    }
    push_vec3(L, vec3_cross(a, b));
    return 1;
}

// ============================================================================
// Ext.Math.Dot(x, y)
// ============================================================================

static int lua_math_dot(lua_State *L) {
    int size_a = get_vec_size(L, 1);
    int size_b = get_vec_size(L, 2);

    if (size_a == 3 && size_b == 3) {
        vec3 a, b;
        parse_vec3_from_table(L, 1, &a);
        parse_vec3_from_table(L, 2, &b);
        lua_pushnumber(L, vec3_dot(a, b));
        return 1;
    } else if (size_a == 4 && size_b == 4) {
        vec4 a, b;
        parse_vec4_from_table(L, 1, &a);
        parse_vec4_from_table(L, 2, &b);
        lua_pushnumber(L, vec4_dot(a, b));
        return 1;
    }

    return luaL_error(L, "Dot requires two vectors of the same size");
}

// ============================================================================
// Ext.Math.Distance(p0, p1)
// ============================================================================

static int lua_math_distance(lua_State *L) {
    int size_a = get_vec_size(L, 1);
    int size_b = get_vec_size(L, 2);

    if (size_a == 3 && size_b == 3) {
        vec3 a, b;
        parse_vec3_from_table(L, 1, &a);
        parse_vec3_from_table(L, 2, &b);
        lua_pushnumber(L, vec3_distance(a, b));
        return 1;
    } else if (size_a == 4 && size_b == 4) {
        vec4 a, b;
        parse_vec4_from_table(L, 1, &a);
        parse_vec4_from_table(L, 2, &b);
        lua_pushnumber(L, vec4_distance(a, b));
        return 1;
    }

    return luaL_error(L, "Distance requires two vectors of the same size");
}

// ============================================================================
// Ext.Math.Length(x)
// ============================================================================

static int lua_math_length(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 3) {
        vec3 v;
        parse_vec3_from_table(L, 1, &v);
        lua_pushnumber(L, vec3_length(v));
        return 1;
    } else if (size == 4) {
        vec4 v;
        parse_vec4_from_table(L, 1, &v);
        lua_pushnumber(L, vec4_length(v));
        return 1;
    }

    return luaL_error(L, "Length requires a vector");
}

// ============================================================================
// Ext.Math.Angle(a, b)
// ============================================================================

static int lua_math_angle(lua_State *L) {
    int size_a = get_vec_size(L, 1);
    int size_b = get_vec_size(L, 2);

    if (size_a == 3 && size_b == 3) {
        vec3 a, b;
        parse_vec3_from_table(L, 1, &a);
        parse_vec3_from_table(L, 2, &b);
        lua_pushnumber(L, vec3_angle(a, b));
        return 1;
    }

    return luaL_error(L, "Angle requires two vec3");
}

// ============================================================================
// Ext.Math.Reflect(I, N)
// ============================================================================

static int lua_math_reflect(lua_State *L) {
    vec3 i, n;
    if (!parse_vec3_from_table(L, 1, &i) || !parse_vec3_from_table(L, 2, &n)) {
        return luaL_error(L, "Reflect requires two vec3");
    }
    push_vec3(L, vec3_reflect(i, n));
    return 1;
}

// ============================================================================
// Ext.Math.Project(x, normal)
// ============================================================================

static int lua_math_project(lua_State *L) {
    vec3 v, n;
    if (!parse_vec3_from_table(L, 1, &v) || !parse_vec3_from_table(L, 2, &n)) {
        return luaL_error(L, "Project requires two vec3");
    }
    push_vec3(L, vec3_project(v, n));
    return 1;
}

// ============================================================================
// Ext.Math.Perpendicular(x, normal)
// ============================================================================

static int lua_math_perpendicular(lua_State *L) {
    vec3 v, n;
    if (!parse_vec3_from_table(L, 1, &v) || !parse_vec3_from_table(L, 2, &n)) {
        return luaL_error(L, "Perpendicular requires two vec3");
    }
    push_vec3(L, vec3_perpendicular(v, n));
    return 1;
}

// ============================================================================
// Matrix Operations
// ============================================================================

static int lua_math_inverse(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 9) {
        mat3 m;
        parse_mat3_from_table(L, 1, &m);
        push_mat3(L, mat3_inverse(m));
        return 1;
    } else if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        push_mat4(L, mat4_inverse(m));
        return 1;
    }

    return luaL_error(L, "Inverse requires a mat3 or mat4");
}

static int lua_math_transpose(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 9) {
        mat3 m;
        parse_mat3_from_table(L, 1, &m);
        push_mat3(L, mat3_transpose(m));
        return 1;
    } else if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        push_mat4(L, mat4_transpose(m));
        return 1;
    }

    return luaL_error(L, "Transpose requires a mat3 or mat4");
}

static int lua_math_determinant(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 9) {
        mat3 m;
        parse_mat3_from_table(L, 1, &m);
        lua_pushnumber(L, mat3_determinant(m));
        return 1;
    } else if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        lua_pushnumber(L, mat4_determinant(m));
        return 1;
    }

    return luaL_error(L, "Determinant requires a mat3 or mat4");
}

static int lua_math_outer_product(lua_State *L) {
    int size_c = get_vec_size(L, 1);
    int size_r = get_vec_size(L, 2);

    if (size_c == 3 && size_r == 3) {
        vec3 c, r;
        parse_vec3_from_table(L, 1, &c);
        parse_vec3_from_table(L, 2, &r);
        push_mat3(L, mat3_outer_product(c, r));
        return 1;
    } else if (size_c == 4 && size_r == 4) {
        vec4 c, r;
        parse_vec4_from_table(L, 1, &c);
        parse_vec4_from_table(L, 2, &r);
        push_mat4(L, mat4_outer_product(c, r));
        return 1;
    }

    return luaL_error(L, "OuterProduct requires two vectors of the same size");
}

// ============================================================================
// Matrix Construction
// ============================================================================

static int lua_math_rotate(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        float angle = luaL_checknumber(L, 2);
        vec3 axis;
        if (!parse_vec3_from_table(L, 3, &axis)) {
            return luaL_error(L, "Rotate requires a mat4, angle, and axis vec3");
        }
        push_mat4(L, mat4_rotate(m, angle, axis));
        return 1;
    }

    return luaL_error(L, "Rotate requires a mat4");
}

static int lua_math_translate(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        vec3 t;
        if (!parse_vec3_from_table(L, 2, &t)) {
            return luaL_error(L, "Translate requires a mat4 and vec3");
        }
        push_mat4(L, mat4_translate(m, t));
        return 1;
    }

    return luaL_error(L, "Translate requires a mat4");
}

static int lua_math_scale(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        vec3 s;
        if (!parse_vec3_from_table(L, 2, &s)) {
            return luaL_error(L, "Scale requires a mat4 and vec3");
        }
        push_mat4(L, mat4_scale_by(m, s));
        return 1;
    }

    return luaL_error(L, "Scale requires a mat4");
}

static int lua_math_build_rotation3(lua_State *L) {
    vec3 axis;
    if (!parse_vec3_from_table(L, 1, &axis)) {
        return luaL_error(L, "BuildRotation3 requires axis vec3");
    }
    float angle = luaL_checknumber(L, 2);
    push_mat3(L, mat3_from_axis_angle(axis, angle));
    return 1;
}

static int lua_math_build_rotation4(lua_State *L) {
    vec3 axis;
    if (!parse_vec3_from_table(L, 1, &axis)) {
        return luaL_error(L, "BuildRotation4 requires axis vec3");
    }
    float angle = luaL_checknumber(L, 2);
    push_mat4(L, mat4_from_axis_angle(axis, angle));
    return 1;
}

static int lua_math_build_translation(lua_State *L) {
    vec3 v;
    if (!parse_vec3_from_table(L, 1, &v)) {
        return luaL_error(L, "BuildTranslation requires vec3");
    }
    push_mat4(L, mat4_translation(v));
    return 1;
}

static int lua_math_build_scale(lua_State *L) {
    vec3 v;
    if (!parse_vec3_from_table(L, 1, &v)) {
        return luaL_error(L, "BuildScale requires vec3");
    }
    push_mat4(L, mat4_scale(v));
    return 1;
}

static int lua_math_build_from_euler_angles3(lua_State *L) {
    vec3 angles;
    if (!parse_vec3_from_table(L, 1, &angles)) {
        return luaL_error(L, "BuildFromEulerAngles3 requires vec3 (pitch, yaw, roll)");
    }
    push_mat3(L, mat3_from_euler_angles(angles));
    return 1;
}

static int lua_math_build_from_euler_angles4(lua_State *L) {
    vec3 angles;
    if (!parse_vec3_from_table(L, 1, &angles)) {
        return luaL_error(L, "BuildFromEulerAngles4 requires vec3 (pitch, yaw, roll)");
    }
    push_mat4(L, mat4_from_euler_angles(angles));
    return 1;
}

static int lua_math_build_from_axis_angle3(lua_State *L) {
    vec3 axis;
    if (!parse_vec3_from_table(L, 1, &axis)) {
        return luaL_error(L, "BuildFromAxisAngle3 requires axis vec3");
    }
    float angle = luaL_checknumber(L, 2);
    push_mat3(L, mat3_from_axis_angle(axis, angle));
    return 1;
}

static int lua_math_build_from_axis_angle4(lua_State *L) {
    vec3 axis;
    if (!parse_vec3_from_table(L, 1, &axis)) {
        return luaL_error(L, "BuildFromAxisAngle4 requires axis vec3");
    }
    float angle = luaL_checknumber(L, 2);
    push_mat4(L, mat4_from_axis_angle(axis, angle));
    return 1;
}

// ============================================================================
// Decomposition
// ============================================================================

static int lua_math_extract_euler_angles(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 9) {
        mat3 m;
        parse_mat3_from_table(L, 1, &m);
        push_vec3(L, mat3_extract_euler_angles(m));
        return 1;
    } else if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        push_vec3(L, mat4_extract_euler_angles(m));
        return 1;
    }

    return luaL_error(L, "ExtractEulerAngles requires a mat3 or mat4");
}

static int lua_math_extract_axis_angle(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        vec3 axis;
        float angle;
        mat4_extract_axis_angle(m, &axis, &angle);
        push_vec3(L, axis);
        lua_pushnumber(L, angle);
        return 2;
    }

    return luaL_error(L, "ExtractAxisAngle requires a mat4");
}

static int lua_math_decompose(lua_State *L) {
    int size = get_vec_size(L, 1);

    if (size == 16) {
        mat4 m;
        parse_mat4_from_table(L, 1, &m);
        vec3 scale, rotation, translation;
        mat4_decompose(m, &scale, &rotation, &translation);
        push_vec3(L, scale);
        push_vec3(L, rotation);
        push_vec3(L, translation);
        return 3;
    }

    return luaL_error(L, "Decompose requires a mat4");
}

// ============================================================================
// Scalar Functions
// ============================================================================

static int lua_math_clamp(lua_State *L) {
    float val = luaL_checknumber(L, 1);
    float min = luaL_checknumber(L, 2);
    float max = luaL_checknumber(L, 3);
    lua_pushnumber(L, math_clamp(val, min, max));
    return 1;
}

static int lua_math_lerp(lua_State *L) {
    // Can be scalar or vector
    int size_x = get_vec_size(L, 1);
    int size_y = get_vec_size(L, 2);

    if (size_x == 3 && size_y == 3) {
        vec3 x, y;
        parse_vec3_from_table(L, 1, &x);
        parse_vec3_from_table(L, 2, &y);
        float a = luaL_checknumber(L, 3);
        push_vec3(L, vec3_lerp(x, y, a));
        return 1;
    } else if (size_x == 4 && size_y == 4) {
        vec4 x, y;
        parse_vec4_from_table(L, 1, &x);
        parse_vec4_from_table(L, 2, &y);
        float a = luaL_checknumber(L, 3);
        push_vec4(L, vec4_lerp(x, y, a));
        return 1;
    }

    // Scalar lerp
    float x = luaL_checknumber(L, 1);
    float y = luaL_checknumber(L, 2);
    float a = luaL_checknumber(L, 3);
    lua_pushnumber(L, math_lerp(x, y, a));
    return 1;
}

static int lua_math_fract(lua_State *L) {
    float x = luaL_checknumber(L, 1);
    lua_pushnumber(L, math_fract(x));
    return 1;
}

static int lua_math_trunc(lua_State *L) {
    float x = luaL_checknumber(L, 1);
    lua_pushnumber(L, math_trunc(x));
    return 1;
}

static int lua_math_sign(lua_State *L) {
    float x = luaL_checknumber(L, 1);
    lua_pushnumber(L, math_sign(x));
    return 1;
}

static int lua_math_acos(lua_State *L) {
    float x = luaL_checknumber(L, 1);
    lua_pushnumber(L, acosf(x));
    return 1;
}

static int lua_math_asin(lua_State *L) {
    float x = luaL_checknumber(L, 1);
    lua_pushnumber(L, asinf(x));
    return 1;
}

static int lua_math_atan(lua_State *L) {
    float x = luaL_checknumber(L, 1);
    lua_pushnumber(L, atanf(x));
    return 1;
}

static int lua_math_atan2(lua_State *L) {
    float y = luaL_checknumber(L, 1);
    float x = luaL_checknumber(L, 2);
    lua_pushnumber(L, atan2f(y, x));
    return 1;
}

static int lua_math_radians(lua_State *L) {
    float deg = luaL_checknumber(L, 1);
    lua_pushnumber(L, math_radians(deg));
    return 1;
}

static int lua_math_degrees(lua_State *L) {
    float rad = luaL_checknumber(L, 1);
    lua_pushnumber(L, math_degrees(rad));
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

void lua_math_register(lua_State *L, int ext_table_index) {
    // Create Ext.Math table
    lua_newtable(L);

    // Vector operations
    lua_pushcfunction(L, lua_math_add);
    lua_setfield(L, -2, "Add");

    lua_pushcfunction(L, lua_math_sub);
    lua_setfield(L, -2, "Sub");

    lua_pushcfunction(L, lua_math_mul);
    lua_setfield(L, -2, "Mul");

    lua_pushcfunction(L, lua_math_div);
    lua_setfield(L, -2, "Div");

    lua_pushcfunction(L, lua_math_normalize);
    lua_setfield(L, -2, "Normalize");

    lua_pushcfunction(L, lua_math_cross);
    lua_setfield(L, -2, "Cross");

    lua_pushcfunction(L, lua_math_dot);
    lua_setfield(L, -2, "Dot");

    lua_pushcfunction(L, lua_math_distance);
    lua_setfield(L, -2, "Distance");

    lua_pushcfunction(L, lua_math_length);
    lua_setfield(L, -2, "Length");

    lua_pushcfunction(L, lua_math_angle);
    lua_setfield(L, -2, "Angle");

    lua_pushcfunction(L, lua_math_reflect);
    lua_setfield(L, -2, "Reflect");

    lua_pushcfunction(L, lua_math_project);
    lua_setfield(L, -2, "Project");

    lua_pushcfunction(L, lua_math_perpendicular);
    lua_setfield(L, -2, "Perpendicular");

    // Matrix operations
    lua_pushcfunction(L, lua_math_inverse);
    lua_setfield(L, -2, "Inverse");

    lua_pushcfunction(L, lua_math_transpose);
    lua_setfield(L, -2, "Transpose");

    lua_pushcfunction(L, lua_math_determinant);
    lua_setfield(L, -2, "Determinant");

    lua_pushcfunction(L, lua_math_outer_product);
    lua_setfield(L, -2, "OuterProduct");

    lua_pushcfunction(L, lua_math_rotate);
    lua_setfield(L, -2, "Rotate");

    lua_pushcfunction(L, lua_math_translate);
    lua_setfield(L, -2, "Translate");

    lua_pushcfunction(L, lua_math_scale);
    lua_setfield(L, -2, "Scale");

    // Matrix construction
    lua_pushcfunction(L, lua_math_build_rotation3);
    lua_setfield(L, -2, "BuildRotation3");

    lua_pushcfunction(L, lua_math_build_rotation4);
    lua_setfield(L, -2, "BuildRotation4");

    lua_pushcfunction(L, lua_math_build_translation);
    lua_setfield(L, -2, "BuildTranslation");

    lua_pushcfunction(L, lua_math_build_scale);
    lua_setfield(L, -2, "BuildScale");

    lua_pushcfunction(L, lua_math_build_from_euler_angles3);
    lua_setfield(L, -2, "BuildFromEulerAngles3");

    lua_pushcfunction(L, lua_math_build_from_euler_angles4);
    lua_setfield(L, -2, "BuildFromEulerAngles4");

    lua_pushcfunction(L, lua_math_build_from_axis_angle3);
    lua_setfield(L, -2, "BuildFromAxisAngle3");

    lua_pushcfunction(L, lua_math_build_from_axis_angle4);
    lua_setfield(L, -2, "BuildFromAxisAngle4");

    // Decomposition
    lua_pushcfunction(L, lua_math_extract_euler_angles);
    lua_setfield(L, -2, "ExtractEulerAngles");

    lua_pushcfunction(L, lua_math_extract_axis_angle);
    lua_setfield(L, -2, "ExtractAxisAngle");

    lua_pushcfunction(L, lua_math_decompose);
    lua_setfield(L, -2, "Decompose");

    // Scalar functions
    lua_pushcfunction(L, lua_math_clamp);
    lua_setfield(L, -2, "Clamp");

    lua_pushcfunction(L, lua_math_lerp);
    lua_setfield(L, -2, "Lerp");

    lua_pushcfunction(L, lua_math_fract);
    lua_setfield(L, -2, "Fract");

    lua_pushcfunction(L, lua_math_trunc);
    lua_setfield(L, -2, "Trunc");

    lua_pushcfunction(L, lua_math_sign);
    lua_setfield(L, -2, "Sign");

    lua_pushcfunction(L, lua_math_acos);
    lua_setfield(L, -2, "Acos");

    lua_pushcfunction(L, lua_math_asin);
    lua_setfield(L, -2, "Asin");

    lua_pushcfunction(L, lua_math_atan);
    lua_setfield(L, -2, "Atan");

    lua_pushcfunction(L, lua_math_atan2);
    lua_setfield(L, -2, "Atan2");

    lua_pushcfunction(L, lua_math_radians);
    lua_setfield(L, -2, "Radians");

    lua_pushcfunction(L, lua_math_degrees);
    lua_setfield(L, -2, "Degrees");

    // Set Ext.Math
    lua_setfield(L, ext_table_index, "Math");
}
