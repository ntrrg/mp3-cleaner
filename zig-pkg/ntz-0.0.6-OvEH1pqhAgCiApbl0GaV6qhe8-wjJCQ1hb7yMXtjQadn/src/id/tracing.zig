// Copyright 2026 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.id.tracing`
//!
//! W3C trace identifier generation.

const std = @import("std");

pub const Mode = enum(u1) {
    pseudo_random,
    secure,
};

pub const Span = [16]u8;
pub const Trace = [32]u8;

pub fn new(
    comptime n: usize,
    io: std.Io,
    mode: Mode,
) std.Io.RandomSecureError![n * 2]u8 {
    var raw: [n]u8 = @splat(0);

    switch (mode) {
        .pseudo_random => io.random(&raw),
        .secure => try io.randomSecure(&raw),
    }

    for (raw) |b| {
        if (b != 0) break;
    } else raw[n - 1] = 1;

    return std.fmt.bytesToHex(raw, .lower);
}

pub fn span(io: std.Io) std.Io.RandomSecureError!Span {
    return new(8, io, .secure);
}

pub fn trace(io: std.Io) std.Io.RandomSecureError!Trace {
    return new(16, io, .secure);
}
