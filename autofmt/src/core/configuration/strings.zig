const Self = []const u8;
const std = @import("std");

pub fn isBlank(self: Self) bool {
    var is_blank = self.len == 0;
    for (self, 0..) |character, character_index| {
        const is_last_character = character_index == self.len - 1;
        if (is_last_character) {
            is_blank = true;
            break;
        }
        if (!std.ascii.isWhitespace(character))
            break;
    }
    return is_blank;
}

pub fn isDelimited(self: Self, prefix: Self, suffix: Self) bool {
    return if (self.len < prefix.len or self.len < suffix.len)
        false
    else
        std.mem.eql(u8, self[0..prefix.len], prefix) and
            std.mem.eql(u8, self[self.len - suffix.len ..], suffix);
}
