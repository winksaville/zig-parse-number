# Zig ParseNumber

ParseNumber returns a struct has a `parse` member that takes a slice and returns a T.

```
pub fn ParseNumber(comptime T: type) type {
    return struct {
        fn parse(str: []const u8) !T {
	    ...
	}
    }
}
```


## Examples

```
test "ParseNumber.parseF32" {
    const parseF32 = ParseNumber(f32).parse;
    var vf32 = try parseF32("123.e4");
    assert(vf32 == f32(123e4));
}
```

## Test
```bash
$ zig test --release-safe parse_number.zig
Test 1/7 ParseNumber.parseIntegerNumber...OK
Test 2/7 ParseNumber.parseFloatNumber...OK
Test 3/7 ParseNumber...OK
Test 4/7 ParseNumber.errors...OK
Test 5/7 ParseNumber.non-u8-sizes...OK
Test 6/7 ParseNumber.non-u8-size-errors...OK
Test 7/7 ParseNumber.parseF32...OK
All tests passed.
```

## Clean
Remove `zig-cache/` directory
```bash
$ rm -rf test ./zig-cache/
```
