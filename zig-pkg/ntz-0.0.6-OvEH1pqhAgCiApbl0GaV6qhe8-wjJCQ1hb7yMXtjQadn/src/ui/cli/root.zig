// Copyright 2026 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.ui.cli`
//!
//! Command line interface implementation. Supports configuration files,
//! environtment variables, flags and arguments.

const std = @import("std");
const Writer = std.Io.Writer;

const types = @import("../../types/root.zig");
const bytes = types.bytes;
const slices = types.slices;

pub const Command = @import("command.zig").Command;

pub const ConfigEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const Entries = slices.Slice(Entry);

pub const Entry = struct {
    const Self = @This();

    kind: enum { config, env, flag, command, argument, arbitrary },
    command: []const u8,
    key: []const u8,
    value: []const u8,

    pub fn init(value: []const u8) Self {
        return .{
            .kind = .arbitrary,
            .command = "",
            .key = "",
            .value = value,
        };
    }
};

pub const Option = @import("option.zig").Option;

// //////////////////////////////
// Help and version generation //
// //////////////////////////////

pub fn writeConfigFileEnv(writer: *Writer, cmd: anytype) !void {
    for (cmd.opts.items()) |opt| {
        if (opt.env.len == 0) continue;

        try writer.writeAll("# ");

        if (opt.id.len > 0) {
            try writer.writeAll(opt.id);
            try writer.writeAll(": ");
        }

        try writer.writeAll(opt.help);

        if (opt.valid_values.len > 0) {
            try writer.writeAll(" (");

            for (opt.valid_values, 0..) |value, i| {
                if (i > 0) try writer.writeAll("|");
                try writer.writeAll(value);
            }

            try writer.writeAll(")");
        }

        try writer.writeAll("\n");

        if (opt.default.len == 0 or opt.has_optional_value)
            try writer.writeAll("#");

        try writer.writeAll(cmd.env_prefix);
        try writer.writeAll(opt.env);
        try writer.writeAll("=");

        if (opt.default.len > 0) {
            try writer.writeAll(opt.default);
        } else {
            try writer.writeAll("<");
            try writer.writeAll(opt.placeholder);
            try writer.writeAll(">");
        }

        try writer.writeAll("\n");
    }

    for (cmd.cmds.items()) |subcmd| {
        try writer.writeAll("\n# ");
        try writer.writeAll(subcmd.id);
        try writer.writeAll("\n");
        try writeConfigFileEnv(writer, subcmd);
    }
}

pub fn writeConfigFileIni(writer: *Writer, cmd: anytype) !void {
    for (cmd.opts.items()) |opt| {
        if (opt.id.len == 0) continue;

        try writer.writeAll("# ");
        try writer.writeAll(opt.help);

        if (opt.valid_values.len > 0) {
            try writer.writeAll(" (");

            for (opt.valid_values, 0..) |value, i| {
                if (i > 0) try writer.writeAll("|");
                try writer.writeAll(value);
            }

            try writer.writeAll(")");
        }

        try writer.writeAll("\n");

        if (opt.default.len == 0 or opt.has_optional_value)
            try writer.writeAll("#");

        try writer.writeAll(opt.id);
        try writer.writeAll("=");

        if (opt.default.len > 0) {
            try writer.writeAll(opt.default);
        } else {
            try writer.writeAll("<");
            try writer.writeAll(opt.placeholder);
            try writer.writeAll(">");
        }

        try writer.writeAll("\n");
    }

    for (cmd.cmds.items()) |subcmd| {
        try writer.writeAll("\n[");
        try writer.writeAll(subcmd.id);
        try writer.writeAll("]\n");
        try writeConfigFileIni(writer, subcmd);
    }
}

pub fn writeHelp(writer: *Writer, cmd: anytype) !void {
    _ = try writeName(writer, cmd);

    if (cmd.description.len > 0) {
        try writer.writeAll(" - ");
        try writer.writeAll(cmd.description);
        try writer.writeAll(".");
    }

    try writer.writeAll("\n");

    // Long description

    if (cmd.longDescription.len > 0) {
        try writer.writeAll("\n");
        try writer.writeAll(cmd.longDescription);
        try writer.writeAll("\n");
    }

    // Usage.

    try writer.writeAll("\n");

    if (cmd.usage.len > 0) {
        try writer.writeAll(cmd.usage);
    } else {
        try writer.writeAll("Usage: ");
        try writer.writeAll(cmd.name);
        try writer.writeAll(" [<options>]\n");
    }

    // Commands, flags and environment variables.

    try writeHelpCommands(writer, cmd, "Commands:");
    try writeHelpFlags(writer, cmd, "Options:");
    try writeHelpEnvVars(writer, cmd, "Environment variables:");
    try writeHelpConfig(writer, cmd, "Configuration:");

    // Epilogue.

    if (cmd.epilog.len > 0) {
        try writer.writeAll("\n");
        try writer.writeAll(cmd.epilog);
        try writer.writeAll("\n");
    }

    // Copyright.

    if (cmd.copyright.len > 0) {
        try writer.writeAll("\n");
        try writer.writeAll(cmd.copyright);
        try writer.writeAll("\n");
    }
}

fn writeHelpCommands(writer: *Writer, cmd: anytype, title: []const u8) !void {
    if (cmd.cmds.len == 0) return;

    var has_title = false;

    for (cmd.cmds.items()) |sub_cmd| {
        if (!has_title and title.len > 0) {
            try writer.writeAll("\n");
            try writer.writeAll(title);
            try writer.writeAll("\n");
            has_title = true;
        }

        try writer.writeAll("  ");
        try writer.writeAll(sub_cmd.name);

        if (sub_cmd.aliases.len > 0) {
            try writer.writeAll(" (");

            for (sub_cmd.aliases, 0..) |alias, i| {
                if (i > 0) try writer.writeAll("|");
                try writer.writeAll(alias);
            }

            try writer.writeAll(")");
        }

        try writer.writeAll(": ");
        try writer.writeAll(sub_cmd.description);
        try writer.writeAll(".\n");
    }
}

fn writeHelpConfig(writer: *Writer, cmd: anytype, title: []const u8) !void {
    if (cmd.opts.len == 0) return;

    var has_title = false;

    for (cmd.opts.items()) |opt| {
        if (opt.id.len == 0) continue;

        if (!has_title and title.len > 0) {
            try writer.writeAll("\n");
            try writer.writeAll(title);
            try writer.writeAll("\n");
            has_title = true;
        }

        try writer.writeAll("  - ");
        try writer.writeAll(opt.id);
        try writer.writeAll(": ");
        try writer.writeAll(opt.help);
        try writer.writeAll(".\n");
    }
}

fn writeHelpFlags(writer: *Writer, cmd: anytype, title: []const u8) !void {
    if (cmd.opts.len == 0) return;

    var has_title = false;

    for (cmd.opts.items()) |opt| {
        if (opt.flags.len == 0) continue;

        if (!has_title and title.len > 0) {
            try writer.writeAll("\n");
            try writer.writeAll(title);
            try writer.writeAll("\n");
            has_title = true;
        }

        try writer.writeAll("  ");

        for (opt.flags, 0..) |flag, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.writeAll(cmd.flags_prefix);
            try writer.writeAll(flag);
            if (opt.is_boolean) continue;
            if (opt.has_optional_value) try writer.writeAll("[");
            try writer.writeAll("=<");
            try writer.writeAll(opt.placeholder);
            try writer.writeAll(">");
            if (opt.has_optional_value) try writer.writeAll("]");
        }

        if (opt.valid_values.len > 0) {
            try writer.writeAll(" (");

            for (opt.valid_values, 0..) |value, i| {
                if (i > 0) try writer.writeAll("|");
                try writer.writeAll(value);
            }

            try writer.writeAll(")");
        }

        if (opt.default.len > 0) {
            try writer.writeAll(" (default: ");
            try writer.writeAll(opt.default);
            try writer.writeAll(")");
        }

        if (opt.id.len > 0) {
            try writer.writeAll(" (id: ");
            try writer.writeAll(opt.id);
            try writer.writeAll(")");
        }

        try writer.writeAll("\n");
        try writer.writeAll("    ");
        try writer.writeAll(opt.help);
        try writer.writeAll(".\n");
    }
}

fn writeHelpEnvVars(writer: *Writer, cmd: anytype, title: []const u8) !void {
    if (cmd.opts.len == 0) return;

    var has_title = false;

    for (cmd.opts.items()) |opt| {
        if (opt.env.len == 0) continue;

        if (!has_title and title.len > 0) {
            try writer.writeAll("\n");
            try writer.writeAll(title);
            try writer.writeAll("\n");
            has_title = true;
        }

        try writer.writeAll("  - ");
        try writer.writeAll(cmd.env_prefix);
        try writer.writeAll(opt.env);

        if (opt.id.len > 0) {
            try writer.writeAll(" (id: ");
            try writer.writeAll(opt.id);
            try writer.writeAll(")");
        }

        try writer.writeAll(": ");
        try writer.writeAll(opt.help);
        try writer.writeAll(".\n");
    }
}

pub fn writeName(writer: *Writer, cmd: anytype) !void {
    if (cmd.parent) |parent| {
        _ = try writeName(writer, parent);
        try writer.writeAll(" ");
    }

    try writer.writeAll(cmd.name);
}

pub fn writeOptionHelp(writer: *Writer, cmd: anytype, id: []const u8) !void {
    for (cmd.opts.items()) |opt| {
        if (!bytes.equal(id, opt.id)) continue;

        if (cmd.parent != null) {
            try writer.writeAll(cmd.id);
            try writer.writeAll(".");
        }

        try writer.writeAll(opt.id);
        try writer.writeAll(" - ");
        try writer.writeAll(opt.help);
        try writer.writeAll("\n\n");

        try writer.writeAll("Required: ");
        try writer.writeAll(if (opt.is_required) "yes" else "no");
        try writer.writeAll("\n");

        try writer.writeAll("Optional value: ");
        try writer.writeAll(if (opt.has_optional_value) "yes" else "no");
        try writer.writeAll("\n");

        if (opt.default.len > 0) {
            try writer.writeAll("Default value: '");
            try writer.writeAll(opt.default);
            try writer.writeAll("'\n");
        }

        if (opt.valid_values.len > 0) {
            try writer.writeAll("Valid values: ");

            for (opt.valid_values, 0..) |value, i| {
                if (i > 0) try writer.writeAll(", ");
                try writer.writeAll("'");
                try writer.writeAll(value);
                try writer.writeAll("'");
            }

            try writer.writeAll("\n");
        }

        if (opt.flags.len > 0) {
            try writer.writeAll("Flags: ");

            for (opt.flags, 0..) |flag, i| {
                if (i > 0) try writer.writeAll(", ");
                try writer.writeAll(cmd.flags_prefix);
                try writer.writeAll(flag);
            }

            try writer.writeAll("\n");
        }

        if (opt.env.len > 0) {
            try writer.writeAll("Environment variable: ");
            try writer.writeAll(cmd.env_prefix);
            try writer.writeAll(opt.env);
            try writer.writeAll("\n");
        }

        if (opt.longHelp.len > 0) {
            try writer.writeAll("\n");
            try writer.writeAll(opt.longHelp);
            try writer.writeAll("\n");
        }

        return;
    }

    return error.InvalidOption;
}

pub fn writeVersion(writer: *Writer, cmd: anytype) !void {
    try writer.writeAll(cmd.name);
    try writer.writeAll(" v");
    try writer.writeAll(cmd.version);
    try writer.writeAll("\n");

    if (cmd.version_info.len > 0) {
        try writer.writeAll(cmd.version_info);
        try writer.writeAll("\n");
    }

    if (cmd.copyright.len > 0) {
        try writer.writeAll(cmd.copyright);
        try writer.writeAll("\n");
    }
}
