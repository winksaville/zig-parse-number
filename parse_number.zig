const std = @import("std");
const debug = std.debug;
const testing = std.testing;
const expect = testing.expect;
const expectError = testing.expectError;
const warn = debug.warn;
const mem = std.mem;
const math = std.math;
const Allocator = mem.Allocator;
const builtin = @import("builtin");
const TypeId = builtin.TypeId;

const DBG = false;
const DBG1 = false;

/// `bytes` is a utf-8 encoded string
pub fn parseFloat(comptime T: type, bytes: []const u8) anyerror!T {
    switch (TypeId(@typeInfo(T))) {
        TypeId.Float => return ParseNumber(T).parse(bytes),
        else => @compileError("Expecting Float"),
    }
}

test "ParseNumber.parseFloat" {
    expect((try parseFloat(f64, "-1.000_001e10")) == -1.000001e10);
    expect((try parseFloat(f32, "0.1")) == 0.1);

    // Couple of examples using ParseNumber directly
    expect((try ParseNumber(i32).parse("0x1234_ABCD")) == 0x1234ABCD);
    const parseF32 = ParseNumber(f32).parse;
    expect((try parseF32("-1.0")) == -1.0);
}

/// The returned struct has a parse member
/// that takes a slice and returns a T.
pub fn ParseNumber(comptime T: type) type {
    return struct {
        const Self = @This();

        pub fn parse(str: []const u8) anyerror!T {
            if (DBG) warn("ParseNumber:+ str={}\n", str);

            var it: U8Iter() = undefined;
            it.set(str, 0);

            var result = try switch (TypeId(@typeInfo(T))) {
                TypeId.Int => parseIntegerNumber(T, &it),
                TypeId.Float => parseFloatNumber(T, &it),
                else => @compileError("Expecting Int or Float"),
            };

            // Skip any trailing WS and if we didn't conusme the entire string it's an error
            _ = it.skipWs();
            if (it.idx < str.len) return error.NoValue;

            if (DBG) warn("ParseNumber:- str={} result={}\n", str, result);
            return result;
        }
    };
}

fn toLower(ch: u8) u8 {
    return if ((ch >= 'A') and (ch <= 'Z')) ch + ('a' - 'A') else ch;
}

fn U8Iter() type {
    return struct {
        const Self = @This();

        initial_idx: usize,
        idx: usize,
        str: []const u8,

        pub fn init(str: []const u8, initial_idx: usize) Self {
            return Self{
                .initial_idx = initial_idx,
                .idx = initial_idx,
                .str = str,
            };
        }

        pub fn set(pSelf: *Self, str: []const u8, initial_idx: usize) void {
            pSelf.initial_idx = initial_idx;
            pSelf.idx = initial_idx;
            pSelf.str = str;
        }

        pub fn done(pSelf: *Self) bool {
            return pSelf.idx >= pSelf.str.len;
        }

        pub fn next(pSelf: *Self) void {
            if (!pSelf.done()) pSelf.idx += 1;
            if (DBG) warn("I: next {}\n", pSelf);
        }

        pub fn curIdx(pSelf: *Self) usize {
            return pSelf.idx;
        }

        pub fn curCh(pSelf: *Self) u8 {
            if (pSelf.done()) return 0;
            return pSelf.str[pSelf.idx];
        }

        pub fn curChLc(pSelf: *Self) u8 {
            return toLower(pSelf.curCh());
        }

        // Peek next character, if end of string
        pub fn peekNextCh(pSelf: *Self) u8 {
            if (pSelf.done()) return 0;
            return pSelf.curCh();
        }

        // Peek Prev character or first character or 0 if end of string
        pub fn peekPrevCh(pSelf: *Self) u8 {
            var idx = if (pSelf.idx > pSelf.initial_idx) pSelf.idx - 1 else pSelf.idx;
            if (pSelf.done()) return 0;
            return pSelf.str[idx];
        }

        // Next character or 0 if end of string
        pub fn nextCh(pSelf: *Self) u8 {
            if (pSelf.done()) return 0;
            var ch = pSelf.str[pSelf.idx];
            pSelf.idx += 1;
            return ch;
        }

        // Prev character or first character or if string is empty 0
        pub fn prevCh(pSelf: *Self) u8 {
            if (pSelf.idx > pSelf.initial_idx) pSelf.idx -= 1;
            return pSelf.peekPrevCh();
        }

        // Next character skipping white space characters or 0 if end of string
        // Ignore ' ':0x20, HT:0x9
        // What about LF:0xA, VT:0xB, FF:0xC, CR:0xD, NEL:0x85, NBS:0xA0?
        // Or other White Space chars: https://en.wikipedia.org/wiki/Whitespace_character
        pub fn skipWs(pSelf: *Self) u8 {
            var ch = pSelf.curCh();
            while ((ch == ' ') or (ch == '\t')) {
                pSelf.next();
                ch = pSelf.curCh();
            }
            if (DBG) warn("SkipWs:- ch='{c}':0x{x} {}\n", ch, ch, pSelf);
            return ch;
        }

        // Next character converted to lower case or 0 if end of string
        pub fn nextChLc(pSelf: *Self) u8 {
            return toLower(pSelf.nextCh());
        }

        // Prev character converted to lower case or 0 the string is empty
        pub fn prevChLc(pSelf: *Self) u8 {
            return toLower(pSelf.prevCh());
        }

        // Next character converted to lower case skipping leading white space character
        pub fn nextChLcSkipWs(pSelf: *Self) u8 {
            return toLower(pSelf.skipWs());
        }
    };
}

fn ParseResult(comptime T: type) type {
    return struct {
        const Self = @This();

        last_idx: usize,
        value: T,
        value_set: bool,
        digits: usize,

        pub fn init() Self {
            //warn("PR: init\n");
            return Self{
                .last_idx = 0,
                .value = 0,
                .value_set = false,
                .digits = 0,
            };
        }

        pub fn reinit(pSelf: *Self) void {
            //warn("PR: reinit\n");
            pSelf.last_idx = 0;
            pSelf.value = 0;
            pSelf.value_set = false;
            pSelf.digits = 0;
        }

        pub fn set(pSelf: *Self, v: T, last_idx: usize, digits: usize) void {
            //warn("PR: set v={} last_idx={}\n", v, last_idx);
            pSelf.last_idx = last_idx;
            pSelf.value = v;
            pSelf.value_set = true;
            pSelf.digits = digits;
        }
    };
}

// Return last charter with 0 if end of string
fn parseNumber(comptime T: type, pIter: *U8Iter(), radix_val: usize) ParseResult(T) {
    var result = ParseResult(T).init();
    pIter.initial_idx = pIter.idx;
    var ch = pIter.nextChLc();

    if (DBG) warn("PN:+  pr={}, it={} ch='{c}':0x{x}\n", result, pIter, ch, ch);
    defer if (DBG) warn("PN:-  pr={} it={} ch='{c}':0x{x}\n", result, pIter, ch, ch);

    var radix = radix_val;
    var value: u128 = 0;
    var negative: bool = false;

    // Handle leading +, -
    if (ch == '-') {
        ch = pIter.nextChLc();
        if (DBG1) warn("PN: neg ch='{c}':0x{x}\n", ch, ch);
        negative = true;
    } else if (ch == '+') {
        ch = pIter.nextChLc();
        if (DBG1) warn("PN: plus ch='{c}':0x{x}\n", ch, ch);
        negative = false;
    }

    // Handle radix if not passed
    if (radix == 0) {
        if ((ch == '0') and !pIter.done()) {
            switch (pIter.nextChLc()) {
                'b' => {
                    radix = 2;
                    ch = pIter.nextChLc();
                },
                'o' => {
                    radix = 8;
                    ch = pIter.nextChLc();
                },
                'd' => {
                    radix = 10;
                    ch = pIter.nextChLc();
                },
                'x' => {
                    radix = 16;
                    ch = pIter.nextChLc();
                },
                else => {
                    radix = 10;
                    ch = pIter.prevChLc();
                },
            }
            if (DBG1) warn("PN: radix={} ch='{c}':0x{x}\n", radix, ch, ch);
        } else {
            radix = 10;
            if (DBG1) warn("PN: default radix={} ch='{c}':0x{x}\n", radix, ch, ch);
        }
    }

    // Handle remaining digits until end of string or an invalid character
    var digits: usize = 0;
    while (ch != 0) : (ch = pIter.nextChLc()) {
        if (DBG1) warn("PN: TOL value={} it={} digits={} ch='{c}':0x{x}\n", value, pIter, digits, ch, ch);
        if (ch == '_') {
            continue;
        }

        var v: u8 = undefined;
        if ((ch >= '0') and (ch <= '9')) {
            v = ch - '0';
        } else if ((ch >= 'a') and (ch <= 'f')) {
            v = 10 + (ch - 'a');
        } else {
            // An invalid character, done
            if (DBG1) warn("PN: bad ch='{c}':0x{x}\n", ch, ch);
            _ = pIter.prevCh();
            break;
        }
        // An invalid character for current radix, done
        if (v >= radix) {
            if (DBG1) warn("PN: v:{} >= radix:{} ch='{c}':0x{x}\n", v, radix, ch, ch);
            _ = pIter.prevCh();
            break;
        }

        value *= radix;
        value += v;
        digits += 1;
    }
    if (DBG1) warn("PN: AL value={} it={} digits={}\n", value, pIter, digits);

    // Only continue if there were digits
    if (digits > 0) {
        if (DBG1) warn("PN: digits > 0 value={}\n", value);
        if (negative) {
            if (DBG1) warn("PN: negative\n");
            value = @bitCast(u128, -1 *% @intCast(i128, value));
        }
        if (DBG1) warn("PN: before T.is_signed value={}\n", value);
        if (T.is_signed) {
            var svalue: i128 = @intCast(i128, value);
            var smax: T = math.maxInt(T);
            var smin: T = math.minInt(T);
            if (DBG1) warn("PN: signed svalue={} smin={} smax={}\n", svalue, smin, smax);
            if (svalue >= math.minInt(T) and svalue <= math.maxInt(T)) {
                result.set(@intCast(T, @intCast(i128, value) & @intCast(T, -1)), pIter.curIdx(), digits);
            }
        } else {
            if (DBG1) warn("PN: after T.is_signed was false value={}\n", value);
            var umax: T = math.maxInt(T);
            if (DBG1) warn("PN:umax={}\n", umax);
            if (value <= math.maxInt(T)) {
                result.set(@intCast(T, value & math.maxInt(T)), pIter.curIdx(), digits);
            }
        }
    }
    return result;
}

fn parseIntegerNumber(comptime T: type, pIter: *U8Iter()) anyerror!T {
    var result = ParseResult(T).init();
    var ch = pIter.skipWs();

    if (DBG) warn("PIN:+ pr={} it={} ch='{c}':0x{x}\n", result, pIter, ch, ch);
    defer if (DBG) warn("PIN:- pr={} it={} ch='{c}':0x{x}\n", result, pIter, ch, ch);

    result = parseNumber(T, pIter, 0);

    if (!result.value_set) {
        if (DBG) warn("PIN: error no value\n");
        return error.NoValue;
    }

    return result.value;
}

fn parseFloatNumber(comptime T: type, pIter: *U8Iter()) anyerror!T {
    var ch = pIter.skipWs();
    var pr = ParseResult(T).init();
    var negative: T = 1;

    if (DBG) warn("PFN:+ pr={} it={} ch='{c}':0x{x}\n", pr, pIter, ch, ch);
    defer if (DBG) warn("PFN:- pr={} it={} ch='{c}':0x{x}\n", pr, pIter, ch, ch);

    if (ch == '-') {
        negative = -1;
        ch = pIter.nextChLc();
    }

    // Get Tens
    var pr_tens = parseNumber(i128, pIter, 10);
    if (pr_tens.value_set) {
        if (DBG1) warn("PFN: pr_tens={} it={} ch='{c}':0x{x}\n", pr_tens, pIter, pIter.curCh(), pIter.curCh());
        var pr_fraction = ParseResult(i128).init();
        var pr_exponent = ParseResult(i128).init();
        if (pIter.curCh() == '.') {
            // Get fraction
            pIter.next();
            pr_fraction = parseNumber(i128, pIter, 10);
            if (!pr_fraction.value_set) {
                if (DBG1) warn("PFN: no fraction\n");
                pr_fraction.set(0, pIter.idx, 0);
            }
        }
        if (DBG1) warn("PFN: pr_fraction={} it={} ch='{c}':0x{x}\n", pr_fraction, pIter, pIter.curCh(), pIter.curCh());
        if (pIter.curCh() == 'e') {
            // Get Exponent
            pIter.next(); // skip e
            pr_exponent = parseNumber(i128, pIter, 10);
            if (!pr_exponent.value_set) {
                if (DBG1) warn("PFN: no exponent\n");
                pr_exponent.set(0, pIter.idx, 0);
            }
        }
        if (DBG1) warn("PFN: pr_exponent={} it={} ch='{c}':0x{x}\n", pr_exponent, pIter, pIter.curCh(), pIter.curCh());

        var tens = @intToFloat(T, pr_tens.value);
        var fraction = @intToFloat(T, pr_fraction.value) / std.math.pow(T, 10, @intToFloat(T, pr_fraction.digits));
        var significand: T = if (pr_tens.value >= 0) tens + fraction else tens - fraction;
        var value = negative * significand * std.math.pow(T, @intToFloat(T, 10), @intToFloat(T, pr_exponent.value));
        pr.set(value, pIter.idx, pr_tens.digits + pr_fraction.digits);

        if (DBG1) warn("PFN: pr.value={}\n", pr.value);
        return pr.value;
    }
    if (DBG) warn("PFN: error no value\n");
    return error.NoValue;
}

test "ParseNumber.parseIntegerNumber" {
    var ch: u8 = undefined;
    var it: U8Iter() = undefined;

    it.set("", 0);
    expectError(error.NoValue, parseIntegerNumber(u8, &it));

    it.set("0", 0);
    var vU8 = try parseIntegerNumber(u8, &it);
    expect(vU8 == 0);
    expect(it.idx == 1);

    it.set("1 2", 0);
    vU8 = try parseIntegerNumber(u8, &it);
    if (DBG) warn("vU8={} it={}\n", vU8, it);
    expect(vU8 == 1);
    expect(it.idx == 1);
    vU8 = try parseIntegerNumber(u8, &it);
    if (DBG) warn("vU8={} it={}\n", vU8, it);
    expect(vU8 == 2);
    expect(it.idx == 3);

    it.set("\t0", 0);
    vU8 = try parseIntegerNumber(u8, &it);
    expect(vU8 == 0);
    expect(it.idx == 2);

    it.set(" \t0", 0);
    vU8 = try parseIntegerNumber(u8, &it);
    expect(vU8 == 0);
    expect(it.idx == 3);

    it.set(" \t 0", 0);
    vU8 = try parseIntegerNumber(u8, &it);
    expect(vU8 == 0);
    expect(it.idx == 4);

    it.set("1.", 0);
    vU8 = try parseIntegerNumber(u8, &it);
    expect(vU8 == 1);
    expect(it.idx == 1);
}

test "ParseNumber.parseFloatNumber" {
    if (DBG) warn("\n");
    var ch: u8 = undefined;
    var it: U8Iter() = undefined;
    var vF32: f32 = undefined;

    it.set("", 0);
    expectError(error.NoValue, parseFloatNumber(f32, &it));

    it.set("0", 0);
    vF32 = try parseFloatNumber(f32, &it);
    expect(vF32 == 0);
    expect(it.idx == 1);

    it.set("1", 0);
    vF32 = try parseFloatNumber(f32, &it);
    expect(vF32 == 1);
    expect(it.idx == 1);

    it.set("+1", 0);
    vF32 = try parseFloatNumber(f32, &it);
    expect(vF32 == 1);
    expect(it.idx == 2);

    it.set("-1", 0);
    vF32 = try parseFloatNumber(f32, &it);
    expect(vF32 == -1);
    expect(it.idx == 2);

    it.set("1.2", 0);
    vF32 = try parseFloatNumber(f32, &it);
    expect(vF32 == 1.2);
    expect(it.idx == 3);

    it.set("1e1", 0);
    vF32 = try parseFloatNumber(f32, &it);
    expect(vF32 == 10);
    expect(it.idx == 3);

    it.set("1.2 3.4", 0);
    vF32 = try parseFloatNumber(f32, &it);
    if (DBG) warn("vF32={} it={}\n", vF32, it);
    expect(vF32 == 1.2);
    expect(it.idx == 3);
    vF32 = try parseFloatNumber(f32, &it);
    if (DBG) warn("vF32={} it={}\n", vF32, it);
    expect(vF32 == 3.4);
    expect(it.idx == 7);
}

test "ParseNumber" {
    expectError(error.NoValue, ParseNumber(u8).parse(""));

    expect((try ParseNumber(u8).parse("0")) == 0);
    expect((try ParseNumber(u8).parse("00")) == 0);
    expect((try ParseNumber(u8).parse(" 1")) == 1);
    expect((try ParseNumber(u8).parse(" 2 ")) == 2);
    expectError(error.NoValue, ParseNumber(u8).parse(" 2d"));

    const s = " \t 123\t";
    var slice = s[0..];
    expect((try ParseNumber(u8).parse(slice)) == 123);

    expect((try ParseNumber(i8).parse("-1")) == -1);
    expect((try ParseNumber(i8).parse("1")) == 1);
    expect((try ParseNumber(i8).parse("+1")) == 1);
    expect((try ParseNumber(i8).parse("01")) == 1);
    expect((try ParseNumber(i8).parse("001")) == 1);
    expect((try ParseNumber(i8).parse("-01")) == -1);
    expect((try ParseNumber(i8).parse("-001")) == -1);

    expect((try ParseNumber(u8).parse("0b0")) == 0);
    expect((try ParseNumber(u8).parse("0b1")) == 1);
    expect((try ParseNumber(u8).parse("0b1010_0101")) == 0xA5);
    expectError(error.NoValue, ParseNumber(u8).parse("0b2"));

    expect((try ParseNumber(u8).parse("0o0")) == 0);
    expect((try ParseNumber(u8).parse("0o1")) == 1);
    expect((try ParseNumber(u8).parse("0o7")) == 7);
    expect((try ParseNumber(u8).parse("0o77")) == 0x3f);
    expect((try ParseNumber(u32).parse("0o111_777")) == 0b1001001111111111);
    expectError(error.NoValue, ParseNumber(u8).parse("0b8"));

    expect((try ParseNumber(u8).parse("0d0")) == 0);
    expect((try ParseNumber(u8).parse("0d1")) == 1);
    expect((try ParseNumber(i8).parse("-0d1")) == -1);
    expect((try ParseNumber(i8).parse("+0d1")) == 1);
    expect((try ParseNumber(u8).parse("0d9")) == 9);
    expect((try ParseNumber(u8).parse("0")) == 0);
    expect((try ParseNumber(u8).parse("9")) == 9);
    expect((try ParseNumber(u8).parse("127")) == 0x7F);
    expect((try ParseNumber(u8).parse("255")) == 255);
    expect((try ParseNumber(u64).parse("123_456_789")) == 123456789);

    expect((try ParseNumber(u8).parse("0x0")) == 0x0);
    expect((try ParseNumber(u8).parse("0x1")) == 0x1);
    expect((try ParseNumber(u8).parse("0x9")) == 0x9);
    expect((try ParseNumber(u8).parse("0xa")) == 0xa);
    expect((try ParseNumber(u8).parse("0xf")) == 0xf);

    expect((try ParseNumber(i128).parse("-170141183460469231731687303715884105728")) == @bitCast(i128, @intCast(u128, 0x80000000000000000000000000000000)));
    expect((try ParseNumber(i128).parse("-170141183460469231731687303715884105727")) == @bitCast(i128, @intCast(u128, 0x80000000000000000000000000000001)));
    expect((try ParseNumber(i128).parse("-1")) == @bitCast(i128, @intCast(u128, 0xffffffffffffffffffffffffffffffff)));
    expect((try ParseNumber(i128).parse("0")) == @bitCast(i128, @intCast(u128, 0x00000000000000000000000000000000)));
    expect((try ParseNumber(i128).parse("170141183460469231731687303715884105726")) == @bitCast(i128, @intCast(u128, 0x7ffffffffffffffffffffffffffffffe)));
    expect((try ParseNumber(i128).parse("170141183460469231731687303715884105727")) == @bitCast(i128, @intCast(u128, 0x7fffffffffffffffffffffffffffffff)));

    expect((try ParseNumber(u128).parse("0")) == 0);
    expect((try ParseNumber(u128).parse("1")) == 1);
    expect((try ParseNumber(u128).parse("340282366920938463463374607431768211454")) == 0xfffffffffffffffffffffffffffffffe);
    expect((try ParseNumber(u128).parse("340282366920938463463374607431768211455")) == 0xffffffffffffffffffffffffffffffff);

    expect((try ParseNumber(u128).parse("0x1234_5678_9ABc_Def0_0FEd_Cba9_8765_4321")) == 0x123456789ABcDef00FEdCba987654321);
    expectError(error.NoValue, ParseNumber(u8).parse("0xg"));

    expect((try ParseNumber(f32).parse("0")) == 0);
    expect((try ParseNumber(f32).parse("-1")) == -1);
    expect((try ParseNumber(f32).parse("1.")) == 1.0);
    expect((try ParseNumber(f32).parse("1e0")) == 1);
    expect((try ParseNumber(f32).parse("1e1")) == 10);
    expect((try ParseNumber(f32).parse("1e-1")) == 0.1);
    expect((try ParseNumber(f32).parse("-0.75780")) == -0.75780);
    expect((try ParseNumber(f64).parse("0.1")) == 0.1);
    expect((try ParseNumber(f64).parse("-1.")) == -1.0);
    expect((try ParseNumber(f64).parse("-2.1")) == -2.1);
    expect((try ParseNumber(f64).parse("-1.2")) == -1.2);
    expect((try ParseNumber(f64).parse("-00.75780")) == -0.75780);
    expect(floatFuzzyEql(f64, try ParseNumber(f64).parse("1.2e2"), 1.2e2, 0.00001));
    expect(floatFuzzyEql(f64, try ParseNumber(f64).parse("-1.2e-2"), -1.2e-2, 0.00001));
}

fn floatFuzzyEql(comptime T: type, lhs: T, rhs: T, fuz: T) bool {
    // Determine which is larger and smallerj
    // then add the fuz to smaller and subract from larger
    // If smaller >= larger then they are equal
    var smaller: T = undefined;
    var larger: T = undefined;
    if (lhs > rhs) {
        larger = lhs - fuz;
        smaller = rhs + fuz;
    } else {
        larger = rhs - fuz;
        smaller = lhs + fuz;
    }
    if (DBG1) warn("smaller={} larger={}\n", smaller, larger);
    return smaller >= larger;
}

test "ParseNumber.errors" {
    expectError(error.NoValue, ParseNumber(u8).parse("-0d1"));
    expectError(error.NoValue, ParseNumber(u8).parse("-1"));
    expectError(error.NoValue, ParseNumber(u8).parse("-127"));
    expectError(error.NoValue, ParseNumber(u8).parse("-128"));
    expectError(error.NoValue, ParseNumber(u8).parse("256"));

    if (!DBG and !DBG1) {
        // Only test if DBG and DBG1 are both false as u0/i1 can't be printed
        expectError(error.NoValue, ParseNumber(u0).parse("1"));

        // Causes error:
        // /home/wink/opt/lib/zig/std/fmt.zig:715:52: error: integer value 1 cannot be implicitly casted to type 'i1'
        //         const new_value = @intCast(uint, -(value + 1)) + 1;
        //expectError(error.NoValue, ParseNumber(i1).parse("1"));
    }

    expectError(error.NoValue, ParseNumber(u1).parse("2"));
    expectError(error.NoValue, ParseNumber(u2).parse("4"));
    expectError(error.NoValue, ParseNumber(u8).parse("256"));
}

test "ParseNumber.non-u8-sizes" {
    if (!DBG and !DBG1) {
        // Only test if DBG and DBG1 are both false as u0/u1 can't be printed
        expect((try ParseNumber(u0).parse("0")) == 0);

        const parseI1 = ParseNumber(i1).parse;
        expect((try parseI1("0")) == 0);
        expect((try parseI1("-1")) == -1);
    }

    const parseU1 = ParseNumber(u1).parse;
    expect((try parseU1("0")) == 0);
    expect((try parseU1("1")) == 1);

    const parseU2 = ParseNumber(u2).parse;
    expect((try parseU2("0")) == 0);
    expect((try parseU2("1")) == 1);
    expect((try parseU2("2")) == 2);
    expect((try parseU2("3")) == 3);

    expect((try ParseNumber(u127).parse("12345678901234567890")) == u127(12345678901234567890));
    expect((try ParseNumber(i127).parse("-12345678901234567890")) == i127(-12345678901234567890));
}

test "ParseNumber.parseF32" {
    const parseF32 = ParseNumber(f32).parse;
    var vf32 = try parseF32("123.e4");
    expect(vf32 == f32(123e4));
}

test "ParseNumber.leading.zeros" {
    const parseF32 = ParseNumber(f32).parse;
    expect((try parseF32("01")) == 1);
    expect((try parseF32("001.001e001")) == 1.001e001);
    expect((try parseF32("-01")) == -1);
    expect((try parseF32("-001.001e-001")) == -1.001e-001);
}

test "ParseNumber.no.leading.digit" {
    // TODO: Should we allow this
    const parseF32 = ParseNumber(f32).parse;
    // expect((try parseF32("0.1")) == f32(.1)); // Zig compiler error
    expectError(error.NoValue, parseF32(".1"));
    expectError(error.NoValue, parseF32("-.1"));
}

test "ParseNumber.trailing.decimal" {
    const parseF32 = ParseNumber(f32).parse;
    expect((try parseF32("0.")) == f32(0.));
    expect((try parseF32("-0.")) == f32(-0.));
    expect((try parseF32("1.")) == f32(1.));
    expect((try parseF32("-1.")) == f32(-1.));
}
