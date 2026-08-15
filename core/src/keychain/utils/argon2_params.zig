pub const min = std.crypto.pwhash.argon2.Params{
    .t = 1,
    .m = 8,
    .p = 1,
};

const std = @import("std");
