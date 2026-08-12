// Copyright © Jean Silva
//
// This file is part of the Key6 open-source project.
//
// Key6 is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// Key6 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see https://www.gnu.org/licenses.

// this is kinda different than what most of the permutation packages that I've
// found do: rather than just providing all possible permutations of a set A, my
// wish is to do so *while* specifying the length n of each permutation.

const std = @import("std");

/// Iterator over every *n*-sized permutation of a slice.
pub fn Iterator(comptime Element: type, permutation_len: usize) type {
    return struct {
        elements: *[]Element,
        relative_swap_index: usize,
        window_index: usize,
        target: Target,
        current_window_swap_count: usize,
        max_swap_per_window_count: usize,

        const Self = @This();
        const Target = enum(u1) {
            left,
            right,

            fn next(self: Target) Target {
                return switch (self) {
                    .left => .right,
                    .right => .left,
                };
            }
        };

        /// Initializes an iterator for computing the *n*-sized permutations
        /// of the given slice.
        pub fn init(elements: *[]Element) Self {
            return .{
                .elements = elements,
                .relative_swap_index = elements.len / 2,
                .window_index = 0,
                .target = .right,
                .current_window_swap_count = 0,
                .max_swap_per_window_count = 0,
            };
        }

        /// Computes the next permutation of the slice, guaranteed to be
        /// different (element- or order-wise) from all other permutations
        /// provided by previous calls to this function *only if* all elements
        /// differ from one anohter.
        ///
        /// In case there aren't any permutations left, null is returned.
        pub fn next(self: *Self) ?[permutation_len]Element {
            // 'max_swap_per_window_count' = 0 denotes that we are consuming the
            // permutations for the first time. because factorials may be
            // expensive to compute, we do so lazily (and only once).
            //
            // this is not so smart, as the integer may overflow pretty fast
            // (apart from its max depending on the word size, too). rather,
            // 'max_swap_per_window_count' could also be lazy, checked and
            // increased up to its upper bound as needed.
            //
            // anyways, something to think of if the use cases for permutations
            // advances more in Key6. works for now.
            if (self.max_swap_per_window_count == 0 and self.elements.len > 0)
                self.max_swap_per_window_count = factorial(self.elements.len);

            const abs_swap_index =
                @min(
                    self.window_index + self.relative_swap_index,
                    self.elements.len -| 1,
                );
            if (!self.hasNext())
                return null;
            const elements = self.elements.*;
            const current_element = elements[abs_swap_index];
            const abs_adjacent_swap_index = switch (self.target) {
                .left => abs_swap_index + 1,
                .right => abs_swap_index - 1,
            };
            self.elements.*[abs_swap_index] = elements[abs_adjacent_swap_index];
            self.elements.*[abs_adjacent_swap_index] = current_element;
            const permutation =
                @as(
                    *[permutation_len]Element,
                    @ptrCast(
                        elements[abs_swap_index -| permutation_len..abs_swap_index].ptr,
                    ),
                ).*;
            self.current_window_swap_count += 1;
            self.target = self.target.next();
            self.relative_swap_index =
                switch (self.target) {
                    .left => self.relative_swap_index / 2 + 1,
                    .right => (self.elements.len - self.relative_swap_index) / 2,
                };
            if (!self.hasNextInCurrentWindow()) {
                if (self.hasNextWindow()) {
                    self.window_index += 1;
                } else {
                    self.window_index = 0;
                }
            }
            return permutation;
        }

        fn hasNext(self: Self) bool {
            return self.hasNextWindow() or self.hasNextInCurrentWindow();
        }

        fn hasNextWindow(self: Self) bool {
            return self.elements.len > 0 and
                self.window_index + self.relative_swap_index + permutation_len <
                    self.elements.len - 1;
        }

        fn hasNextInCurrentWindow(self: Self) bool {
            return self.current_window_swap_count <
                self.max_swap_per_window_count;
        }
    };
}

fn factorial(n: usize) usize {
    if (n == 0)
        return 1;

    // this seems oddly inneficient…
    // isn't there an instruction or a coprocessor for computing factorials? :p
    var result: usize = n;
    var m: usize = n - 1;
    while (m >= 1) : (m -= 1)
        result *= m;
    return result;
}

test Iterator {
    empty: {
        var backing_elements = [_]u2{};
        var elements: []u2 = backing_elements[0..];
        var iter = Iterator(u2, 2).init(&elements);
        try std.testing.expectEqual(null, iter.next());
        break :empty;
    }

    var backing_elements = [_]u2{ 1, 2, 3 };
    var elements: []u2 = backing_elements[0..];
    var iter = Iterator(u2, 2).init(&elements);
    try std.testing.expectEqualSlices(u2, &.{ 2, 1 }, &iter.next().?);
    try std.testing.expectEqualSlices(u2, &.{ 2, 3 }, &iter.next().?);
    try std.testing.expectEqualSlices(u2, &.{ 3, 2 }, &iter.next().?);
    try std.testing.expectEqualSlices(u2, &.{ 3, 1 }, &iter.next().?);
    try std.testing.expectEqualSlices(u2, &.{ 1, 3 }, &iter.next().?);
    try std.testing.expectEqualSlices(u2, &.{ 1, 2 }, &iter.next().?);
    try std.testing.expectEqual(null, iter.next());
}

test factorial {
    try std.testing.expectEqual(1, factorial(0));
    try std.testing.expectEqual(1, factorial(1));
    try std.testing.expectEqual(2, factorial(2));
    try std.testing.expectEqual(6, factorial(3));
    try std.testing.expectEqual(479001600, factorial(12));
}
