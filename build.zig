const std = @import("std");
const build_zon: Manifest = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    // //////////
    // Options //
    // //////////

    const build_cache = b.option(
        []const u8,
        "cache",
        "Cache key to manage Zig cache programmatically",
    ) orelse "";

    const name = b.option(
        []const u8,
        "name",
        "Binary name",
    ) orelse "mp3-cleaner";

    const version = b.option(
        []const u8,
        "version",
        "Binary version, using semantic version format",
    ) orelse build_zon.version;

    // Compilation.

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dynamic_link = b.option(
        bool,
        "dynamic",
        "Produce dynamically linked binaries",
    ) orelse false;

    const error_tracing = b.option(
        bool,
        "error-tracing",
        "Enable error traces (enabled by default with Debug and ReleaseSafe)",
    );

    const link_libc = b.option(
        bool,
        "libc",
        "Link C library",
    );

    const use_llvm = b.option(
        bool,
        "llvm",
        "Use LLVM backend",
    );

    const pic = b.option(
        bool,
        "pic",
        "Enable Position Independent Code",
    );

    const single_threaded = b.option(
        bool,
        "single-threaded",
        "Produce single threaded binaries",
    );

    const strip = b.option(
        bool,
        "strip",
        "Produce striped binaries",
    );

    const sanitize_thread = b.option(
        bool,
        "thread-sanitizer",
        "Enable thread sanitizer",
    );

    // Testing.

    const test_build = b.option(
        bool,
        "test-build",
        "Include test executable in regular builds",
    ) orelse false;

    const test_coverage = b.option(
        bool,
        "test-coverage",
        "Generate test coverage reports",
    ) orelse false;

    const test_coverage_cmd = b.option(
        []const u8,
        "test-coverage-cmd",
        "Command used for generating coverage reports",
    ) orelse "tools/kcov";

    const test_coverage_out = b.option(
        []const u8,
        "test-coverage-out",
        "Coverage reports destination",
    ) orelse ".zig-cache/coverage";

    const test_file = b.option(
        []const u8,
        "test-file",
        "Use given file as tests root file",
    ) orelse "src/cleaner/root_test.zig";

    const test_filter = b.option(
        []const u8,
        "test-filter",
        "Run tests that match given filter",
    );

    const test_slow = b.option(
        bool,
        "test-slow",
        "Run slow tests",
    ) orelse true;

    // Profilling.

    const debug_valgrind = b.option(
        bool,
        "debug-valgrind",
        "Produce Valgrind friendly binaries",
    );

    // ///////////////
    // Dependencies //
    // ///////////////

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "name", name);
    build_options.addOption([]const u8, "version", version);
    build_options.addOption([]const u8, "build_cache", build_cache);

    const build_options_mod = build_options.createModule();

    // ntz
    const ntz_mod = b.dependency("ntz", .{}).module("ntz");

    // ////////
    // Build //
    // ////////

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .single_threaded = single_threaded,
        .strip = strip,
        .sanitize_thread = sanitize_thread,
        .valgrind = debug_valgrind,
        .pic = pic,
        .error_tracing = error_tracing,
    });

    exe_mod.addImport("build_options", build_options_mod);
    exe_mod.addImport("ntz", ntz_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .version = std.SemanticVersion.parse(version) catch |err| {
            std.debug.panic("invalid version format: {}", .{err});
        },

        .root_module = exe_mod,
        .linkage = if (dynamic_link) .dynamic else .static,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });

    b.installArtifact(exe);

    // //////
    // Run //
    // //////

    const run_step = b.step("run", "Build and run the main binary");
    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();

    run.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run.step);

    // //////////
    // Testing //
    // //////////

    const test_step = b.step("test", "Run tests");

    const test_mod = b.createModule(.{
        .root_source_file = b.path(test_file),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .single_threaded = single_threaded,
        .strip = strip,
        .sanitize_thread = sanitize_thread,
        .valgrind = debug_valgrind,
        .pic = pic,
        .error_tracing = error_tracing,
    });

    const test_options = b.addOptions();
    test_options.addOption(bool, "run_slow", test_slow);

    test_mod.addImport("test_options", test_options.createModule());
    test_mod.addImport("build_options", build_options_mod);
    test_mod.addImport("ntz", ntz_mod);

    const test_exe = b.addTest(.{
        .name = b.fmt("{s}-test", .{name}),
        .root_module = test_mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
        .test_runner = null,
        .use_llvm = use_llvm,
        .use_lld = use_llvm,
    });

    if (test_build) {
        b.installArtifact(test_exe);
    }

    const test_run = b.addRunArtifact(test_exe);
    test_step.dependOn(&test_run.step);

    // Coverage.

    if (test_coverage) {
        const coverage_cmd = b.addSystemCommand(&.{test_coverage_cmd});

        coverage_cmd.addArgs(&.{
            "--clean",
            "--include-pattern=ntz/src",
            "--exclude-pattern=_test.zig",
            test_coverage_out,
        });

        coverage_cmd.addArtifactArg2(test_exe, .{});
        coverage_cmd.has_side_effects = true;

        test_step.dependOn(&coverage_cmd.step);
    }

    // /////
    // QA //
    // /////

    const fmt_step = b.step("fmt", "Format source code");

    const zig_fmt = b.addFmt(.{ .paths = b.pathList(&.{
        "build.zig.zon",
        "build.zig",
        "src",
    }) });

    fmt_step.dependOn(&zig_fmt.step);

    // CI

    const ci_step = b.step("ci", "Run continuous integration checks");
    ci_step.dependOn(&zig_fmt.step);
    ci_step.dependOn(b.getInstallStep());
    ci_step.dependOn(test_step);

    // ////////////////
    // Documentation //
    // ////////////////

    const ntz_docs = b.addInstallDirectory(.{
        .source_dir = exe.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&ntz_docs.step);
}

const Manifest = struct {
    name: enum(u1) { mp3_cleaner },
    fingerprint: u64,
    minimum_zig_version: []const u8,
    version: []const u8,
    dependencies: Dependencies,
    paths: []const []const u8,
};

const Dependency = struct {
    path: []const u8 = "",

    url: []const u8 = "",
    hash: []const u8 = "",
    lazy: bool = false,
};

const Dependencies = struct {
    ntz: Dependency,
};
