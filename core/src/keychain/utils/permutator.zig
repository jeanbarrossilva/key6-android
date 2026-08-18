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

const std = @import("std");

/// Iterator over every *k*-sized ordered subset of an *n*-sized slice, where
/// *k* ≤ *n*.
pub fn Iterator(comptime Element: type, k: usize) type {
    return struct {
        /// Pointer to the slice over whose permutations this iterator may
        /// iterate.
        s_ptr: *[]Element,

        /// Index of the element to be swapped with the element adjacent to it,
        /// relative to the window; thus, rather than an index of `s_ptr.*`,
        /// this is an index of the subset `s_ptr.*[window..k]`.
        rel_swap: usize,

        /// Index of the current window in the slice `s_ptr.*`. In this context,
        /// a window is a subset of length `k` of such slice, the first window
        /// is at `s_ptr.*[0]`, with subsequent ones being at
        /// `s_ptr.*[(i + 1) * n]`, where *i* is the amount of times `next()`
        /// has been called before.
        window: usize,

        /// Amount of swaps in the current window `s_ptr.*[window..k]` since the
        /// last iteration.
        ///
        /// The maximum value of this field is denoted by `max_swaps`, which is
        /// `k`! after the first call to `next()`. Once this maximum has been
        /// reached, a posterior iteration will cause this field to be zeroed,
        /// as that implies that we've moved to the next window.
        swap: usize,

        /// Maximum amount of swaps that can occur in the window
        /// `s_ptr.*[window..k]`. As an optimization, given that this equals to
        /// `k`! conceptually, this field is first set to zero, with `k`! being
        /// computed and assigned to it once, upon the first iteration.
        max_swaps: usize,

        const Self = @This();

        /// Initializes an iterator for computing the *k*-sized ordered subsets
        /// of the given slice.
        pub fn init(s_ptr: *[]Element) Self {
            return .{
                .s_ptr = s_ptr,
                .rel_swap = s_ptr.len / 2,
                .window = 0,
                .swap = 0,
                .max_swaps = 0,
            };
        }

        /// Computes the next permutation of the slice, guaranteed to be
        /// different (element- and order-wise) from all other permutations
        /// provided by previous calls to this function *only if* all elements
        /// differ from one another.
        ///
        /// In case there aren't any permutations left, null is returned.
        pub fn next(self: *Self) ?[k]Element {
            const n = self.s_ptr.len;
            if (self.max_swaps == 0 and n > 0) {
                // this is not so smart: the integer may overflow pretty fast
                // (apart from its max depending on the word size, too). rather,
                // 'max_swaps' could also be lazy, checked and increased toward
                // its upper bound as needed.
                self.max_swaps = factorial(n);
            }
            if (!self.hasNext())
                return null;
            const abs_swap = @min(self.window + self.rel_swap, n -| 1);
            const s = self.s_ptr.*;
            const swapped = s[abs_swap];
            const abs_adj_swap =
                if (self.swap % 2 == 0) abs_swap -| 1 else abs_swap + 1;
            self.s_ptr.*[abs_swap] = s[abs_adj_swap];
            self.s_ptr.*[abs_adj_swap] = swapped;
            const result =
                @as(*[k]Element, @ptrCast(s[abs_swap -| k..abs_swap].ptr)).*;
            self.swap += 1;
            self.rel_swap =
                if (abs_adj_swap % 2 != 0)
                    self.rel_swap / 2
                else
                    (n - self.rel_swap) / 2;
            if (!self.hasNextInCurrentWindow())
                self.window =
                    if (self.hasNextWindow()) self.window + 1 else 0;
            return result;
        }

        fn hasNext(self: Self) bool {
            return self.hasNextWindow() or self.hasNextInCurrentWindow();
        }

        fn hasNextWindow(self: Self) bool {
            return self.s_ptr.len > 0 and
                self.window + self.rel_swap + k < self.s_ptr.len - 1;
        }

        fn hasNextInCurrentWindow(self: Self) bool {
            return self.swap < self.max_swaps;
        }
    };
}

fn factorial(n: usize) usize {
    if (n == 0)
        return 1;
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
