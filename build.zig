const std = @import("std");

pub fn build(b: *std.Build) void {
    const default_name = "mp3-cleaner";
    const default_version = "0.0.1";

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dynamic_link = b.option(
        bool,
        "dynamic",
        "produce dynamically linked binaries",
    ) orelse false;

    const name = b.option(
        []const u8,
        "name",
        "string to use as program name",
    ) orelse default_name;

    const single_threaded = b.option(
        bool,
        "single-threaded",
        "produce single threaded binaries",
    ) orelse false;

    const strip = b.option(
        bool,
        "strip",
        "produce striped binaries",
    ) orelse switch (optimize) {
        .Debug, .ReleaseSafe => false,
        .ReleaseFast, .ReleaseSmall => true,
    };

    const test_coverage = b.option(
        bool,
        "test-coverage",
        "produce test coverage reports",
    ) orelse false;

    const test_coverage_cmd = b.option(
        []const u8,
        "test-coverage-cmd",
        "coverage tool used for generating reports",
    ) orelse "kcov";

    const test_filter = b.option(
        []const u8,
        "test-filter",
        "run tests that match the given filter",
    );

    const version = b.option(
        []const u8,
        "version",
        "string to use as program version",
    ) orelse default_version;

    // ///////////////
    // Dependencies //
    // ///////////////

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "name", name);
    build_options.addOption([]const u8, "version", version);

    const build_options_module = build_options.createModule();

    // ntz

    //const ntz_module = b.dependency("ntz", .{}).module("ntz");

    const ntz_module = b.addModule("ntz", .{
        .root_source_file = .{ .path = "src/ntz/ntz.zig" },
    });

    // ////////
    // Build //
    // ////////

    const exe = b.addExecutable(.{
        .name = name,
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .linkage = if (dynamic_link) .dynamic else .static,
        .single_threaded = single_threaded,
    });

    exe.root_module.addImport("build_options", build_options_module);
    exe.root_module.addImport("ntz", ntz_module);
    b.installArtifact(exe);

    // //////
    // Run //
    // //////

    const run_step = b.step("run", "build and run the main binary");
    const run = b.addRunArtifact(exe);

    if (b.args) |args| {
        run.addArgs(args);
    }

    run.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run.step);

    // //////////
    // Testing //
    // //////////

    const test_step = b.step("test", "run tests");

    const tests: []const []const u8 = if (b.args) |args|
        args
    else
        &.{"src/main_test.zig"};

    for (tests) |test_file| {
        const test_exe = b.addTest(.{
            .root_source_file = .{ .path = test_file },
            .target = target,
            .optimize = optimize,
            .single_threaded = single_threaded,
            .filter = test_filter,
        });

        test_exe.root_module.addImport("build_options", build_options_module);
        test_exe.root_module.addImport("ntz", ntz_module);

        const test_run = b.addRunArtifact(test_exe);
        test_step.dependOn(&test_run.step);

        // Coverage.

        if (test_coverage) {
            //const coverage_output_path = b.makeTempPath();
            //const test_install = b.addInstallArtifact(test_exe, .{});
            //test_install.dest_dir = .prefix;
            //test_install.dest_sub_path = b.fmt("tmp/{s}/tests", .{name});

            const coverage_cmd = b.addSystemCommand(&.{
                test_coverage_cmd,
                "--include-pattern=/src",
                "coverage",
            });

            coverage_cmd.addArtifactArg(test_exe);
            coverage_cmd.has_side_effects = true;

            test_step.dependOn(&b.addRemoveDirTree("coverage").step);
            test_step.dependOn(&coverage_cmd.step);
        }
    }

    // /////
    // QA //
    // /////

    const fmt_step = b.step("fmt", "format source code");
    const zig_fmt = b.addFmt(.{ .paths = &.{ "build.zig", "src" } });
    fmt_step.dependOn(&zig_fmt.step);

    // CI

    const ci_step = b.step("ci", "run continuos integration checks");
    ci_step.dependOn(&zig_fmt.step);
    ci_step.dependOn(b.getInstallStep());
    ci_step.dependOn(test_step);
    //ci_step.dependOn(coverage_step);
}

//fn modulesFromDir(p: [:0]const u8, name: [:0]const u8, ctx: struct {
//    allocator: mem.Allocator,
//}) !void {
//    const ally = ctx.allocator;
//
//    var dir = fs.cwd().openIterableDir(p, .{}) catch |err| {
//        log.err("cannot open '{s}': {}", .{ p, err });
//        return err;
//    };
//
//    defer dir.close();
//
//    var walker = dir.walk(ally) catch |err| {
//        log.err("cannot generate iterator for '{s}': {}", .{ p, err });
//        return err;
//    };
//
//    defer walker.deinit();
//
//    while (walker.next()) |entry_opt| {
//        const entry = entry_opt orelse break;
//
//        if (entry.kind != .file and entry.kind != .sym_link) continue;
//        if (!mem.endsWith(u8, entry.basename, ".zig")) continue;
//
//        const mod_name = mod_name: {
//            const dirname = try path.join(ally, &.{
//                name,
//                path.dirname(entry.path) orelse "",
//            });
//
//            const basename = entry.basename[0 .. entry.basename.len - 4];
//
//            if (mem.endsWith(u8, dirname, basename))
//                break :mod_name dirname;
//
//            break :mod_name try path.join(ally, &.{ dirname, basename });
//        };
//
//        const mod_path = try path.join(ally, &.{ p, entry.path });
//
//        log.debug("{s} -> {s}", .{ mod_path, mod_name });
//    } else |err| {
//        log.err("cannot iterate over '{s}': {}", .{ p, err });
//        return err;
//    }
//}
