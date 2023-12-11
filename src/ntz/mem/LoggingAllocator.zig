const std = @import("std");
const mem = std.mem;

const Self = @This();

ally: mem.Allocator,
current: usize,
max: usize,
allocated: usize,
freed: usize,

pub fn init(ally: mem.Allocator) Self {
    return .{
        .ally = ally,
        .current = 0,
        .max = 0,
        .allocated = 0,
        .freed = 0,
    };
}

pub fn allocator(self: *Self) mem.Allocator {
    return .{
        .ptr = self,

        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .free = free,
        },
    };
}

fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
    const self: *Self = @ptrCast(@alignCast(ctx));
    const result = self.ally.rawAlloc(len, ptr_align, ret_addr);

    if (result != null) {
        self.allocated +|= len;
        self.current +|= len;
        if (self.current > self.max) self.max = self.current;
    }

    //std.debug.print("\n--------------------------------------------\n", .{});
    //std.debug.writeCurrentStackTrace(
    //    std.io.getStdErr().writer(),
    //    std.debug.getSelfDebugInfo() catch unreachable,
    //    .escape_codes,
    //    @returnAddress(),
    //) catch unreachable;

    return result;
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    ptr_align: u8,
    new_len: usize,
    ret_addr: usize,
) bool {
    const self: *Self = @ptrCast(@alignCast(ctx));
    const result = self.ally.rawResize(buf, ptr_align, new_len, ret_addr);

    if (result) {
        if (new_len > buf.len) {
            self.allocated +|= new_len - buf.len;
            self.current +|= new_len - buf.len;
            if (self.current > self.max) self.max = self.current;
        } else if (new_len < buf.len) {
            self.allocated +|= buf.len - new_len;
            self.current +|= buf.len - new_len;
        }
    }

    return result;
}

fn free(ctx: *anyopaque, buf: []u8, ptr_align: u8, ret_addr: usize) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.ally.rawFree(buf, ptr_align, ret_addr);
    self.current -|= buf.len;
    self.freed +|= buf.len;
}
