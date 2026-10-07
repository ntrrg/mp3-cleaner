// Copyright 2025 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.iterators`
//!
//! Utilities for working with iterators.

/// A common interface for iterators.
pub fn Iterator(
    comptime T: type,
    comptime Index: type,
    comptime Item: type,
    comptime IterationError: ?type,
    comptime nextIndexFn: fn (it: *T, current_index: Index) if (IterationError) |Err| Err!Index else Index,
    comptime getItemFn: fn (it: *T, index: Index) if (IterationError) |Err| Err!?Item else ?Item,
) type {
    return struct {
        const Self = @This();
        pub const Error = if (IterationError) |Err| Err else void{};
        pub const Result = struct { index: Index, item: ?Item };
        pub const ResultIndex = if (IterationError) |Err| Err!Index else Index;
        pub const ResultItem = if (IterationError) |Err| Err!?Item else ?Item;
        pub const Skip = if (IterationError) |Err| Err!void else void;

        ctx: T,
        index: Index,

        /// Returns the item on the given index.
        pub fn get(it: *Self, index: Index) ResultItem {
            return getItemFn(&it.ctx, index);
        }

        /// Returns the next item.
        pub fn next(it: *Self) ResultItem {
            if (comptime IterationError) |_| {
                const item = try getItemFn(&it.ctx, it.index);
                it.index = try nextIndexFn(&it.ctx, it.index);
                return item;
            } else {
                const item = getItemFn(&it.ctx, it.index) orelse return null;
                it.index = nextIndexFn(&it.ctx, it.index);
                return item;
            }
        }

        /// Returns the next item and its index.
        pub fn nextResult(it: *Self) if (IterationError) |Err| Err!Result else Result {
            const i = it.index;

            const item = if (comptime IterationError) |_|
                try getItemFn(&it.ctx, i)
            else
                getItemFn(&it.ctx, i);

            it.index = if (comptime IterationError) |_|
                try nextIndexFn(&it.ctx, i)
            else
                nextIndexFn(&it.ctx, i);

            return .{ .index = i, .item = item };
        }

        /// Returns the index of the next item.
        ///
        /// The current iteration index is not modified.
        pub fn nextIndex(it: *Self) ResultIndex {
            return nextIndexFn(&it.ctx, it.index);
        }

        /// Returns the next item.
        ///
        /// The current iteration index is not modified.
        pub fn peek(it: *Self) ResultItem {
            return it.peekN(1);
        }

        /// Returns the `n`th item after the current item.
        ///
        /// The current iteration index is not modified.
        pub fn peekN(it: *Self, n: usize) ResultItem {
            const result = if (comptime IterationError) |_|
                try it.peekResultN(n)
            else
                it.peekResultN(n);

            return result.item;
        }

        /// Returns the next item and its index.
        ///
        /// The current iteration index is not modified.
        pub fn peekResult(it: *Self) if (IterationError) |Err| Err!Result else Result {
            return it.peekResultN(1);
        }

        /// Returns the `n`th item and its index after the current item.
        ///
        /// The current iteration index is not modified.
        pub fn peekResultN(it: *Self, n: usize) if (IterationError) |Err| Err!Result else Result {
            var i = it.index;

            for (1..if (n > 0) n else 1) |_| {
                i = if (comptime IterationError) |_|
                    try nextIndexFn(&it.ctx, i)
                else
                    nextIndexFn(&it.ctx, i);
            }

            const item = if (comptime IterationError) |_|
                try getItemFn(&it.ctx, i)
            else
                getItemFn(&it.ctx, i);

            return .{ .index = i, .item = item };
        }

        /// Skips the next item.
        pub fn skip(it: *Self) Skip {
            return it.skipN(1);
        }

        /// Skips the next `n` items.
        pub fn skipN(it: *Self, n: usize) Skip {
            var i = it.index;

            for (0..if (n > 0) n else 1) |_| {
                i = if (comptime IterationError) |_|
                    try nextIndexFn(&it.ctx, i)
                else
                    nextIndexFn(&it.ctx, i);
            }

            it.index = i;
        }
    };
}
