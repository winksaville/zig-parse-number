# Zig ParseNumber

/// The returned struct has a parse member
/// that takes a slice and returns a T.
pub fn ParseNumber(comptime T: type) type;

## Examples

test "ParseNumber.parseF32" {
    const parseF32 = ParseNumber(f32).parse;
    var vf32 = try parseF32("123.e4");
    assert(vf32 == f32(123e4));
}

## Test
```bash
$ zig test parse_number.zig 
Test 1/4 ParseNumber.parseIntegerNumber...OK
Test 2/4 ParseNumber.parseFloatNumber...OK
Test 3/4 ParseNumber...OK
Test 4/4 ParseNumber.parseF32...OK
All tests passed.
```

## Clean
Remove `zig-cache/` directory
```bash
$ rm -rf test ./zig-cache/
```
