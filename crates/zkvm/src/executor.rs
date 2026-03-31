use std::sync::Arc;
use parking_lot::RwLock;
use crate::{ZkVmResult, ZkVmError, PagePermissions};
use std::cmp;
use std::collections::BTreeMap;

/// Represents a secure execution context within the ZKVM
pub struct Executor {
    /// Memory address space for this executor
    address_space: Arc<RwLock<AddressSpace>>,
    /// Current execution state
    state: ExecutorState,
    /// Execution flags and settings
    #[allow(dead_code)] // Will be used when implementing execution time limits and JIT
    flags: ExecutionFlags,
}

/// Represents the state of code execution
#[derive(Debug, Clone, Copy)]
struct ExecutorState {
    /// Program counter
    pc: u64,
    /// Stack pointer
    #[allow(dead_code)] // Will be used when implementing stack operations
    sp: u64,
    /// Base pointer
    #[allow(dead_code)] // Will be used when implementing function calls
    bp: u64,
    /// Status flags
    #[allow(dead_code)] // Will be used when implementing conditional operations
    flags: u32,
    /// General purpose registers (R0-R15)
    registers: [u32; 16],
}

impl ExecutorState {
    /// Create a new executor state
    #[allow(dead_code)] // Will be used when implementing VM state management
    fn new() -> Self {
        Self {
            pc: 0,
            sp: 0x7FFFFFFF, // Start at high memory for stack
            bp: 0x7FFFFFFF,
            flags: 0,
            registers: [0; 16],
        }
    }
    
    /// Push value onto stack with overflow protection
    #[allow(dead_code)] // Will be used when implementing stack operations
    fn push_stack(&mut self, _value: u32) -> ZkVmResult<()> {
        // Check for stack pointer underflow
        self.sp = self.sp.checked_sub(4)
            .ok_or_else(|| ZkVmError::ExecutionError(
                "Stack pointer underflow".into()
            ))?;
        
        // In a real implementation, this would also check stack bounds
        // and write the value to memory
        Ok(())
    }
    
    /// Pop value from stack with overflow protection
    #[allow(dead_code)] // Will be used when implementing stack operations
    fn pop_stack(&mut self) -> ZkVmResult<u32> {
        // In a real implementation, this would read from memory at sp
        let value = 0;
        
        // Check for stack pointer overflow
        self.sp = self.sp.checked_add(4)
            .ok_or_else(|| ZkVmError::ExecutionError(
                "Stack pointer overflow".into()
            ))?;
        
        Ok(value)
    }
    
    /// Set status flags
    #[allow(dead_code)] // Will be used when implementing CPU flag operations
    fn set_flags(&mut self, zero: bool, negative: bool, carry: bool, overflow: bool) {
        self.flags = 0;
        if zero { self.flags |= 0x01; }
        if negative { self.flags |= 0x02; }
        if carry { self.flags |= 0x04; }
        if overflow { self.flags |= 0x08; }
    }
    
    /// Check if zero flag is set
    #[allow(dead_code)] // Will be used when implementing conditional operations
    fn is_zero(&self) -> bool {
        (self.flags & 0x01) != 0
    }
    
    /// Set up function call frame with error handling
    #[allow(dead_code)] // Will be used when implementing function calls
    fn setup_call_frame(&mut self, return_address: u64) -> ZkVmResult<()> {
        self.push_stack(self.bp as u32)?; // Save old base pointer
        self.bp = self.sp; // Set new base pointer
        self.push_stack(return_address as u32)?; // Save return address
        Ok(())
    }
    
    /// Restore from function call with error handling
    #[allow(dead_code)] // Will be used when implementing function calls
    fn restore_call_frame(&mut self) -> ZkVmResult<()> {
        self.sp = self.bp; // Restore stack pointer
        self.bp = self.pop_stack()? as u64; // Restore base pointer
        Ok(())
    }
}

/// Configuration flags for execution
#[derive(Debug, Clone)]
struct ExecutionFlags {
    /// Whether to enable JIT compilation
    #[allow(dead_code)] // Will be used when implementing JIT compilation
    enable_jit: bool,
    /// Maximum memory usage allowed
    #[allow(dead_code)] // Will be used when implementing memory limits
    memory_limit: usize,
    /// Maximum execution time in milliseconds
    #[allow(dead_code)] // Will be used when implementing execution time limits
    time_limit: u64,
}

impl ExecutionFlags {
    /// Create default execution flags
    #[allow(dead_code)] // Will be used when implementing execution configuration
    fn default() -> Self {
        Self {
            enable_jit: false,
            memory_limit: 1024 * 1024 * 16, // 16MB default
            time_limit: 5000, // 5 seconds default
        }
    }
    
    /// Create execution flags with JIT enabled
    #[allow(dead_code)] // Will be used when implementing JIT compilation
    fn with_jit() -> Self {
        Self {
            enable_jit: true,
            ..Self::default()
        }
    }
    
    /// Check if execution should timeout
    #[allow(dead_code)] // Will be used when implementing execution time limits
    fn should_timeout(&self, elapsed_ms: u64) -> bool {
        elapsed_ms >= self.time_limit
    }
    
    /// Check if JIT compilation is enabled
    #[allow(dead_code)] // Will be used when implementing JIT compilation
    fn jit_enabled(&self) -> bool {
        self.enable_jit
    }
}

/// Represents a virtual address space
struct AddressSpace {
    /// Memory segments sorted by base address
    segments: BTreeMap<u64, MemorySegment>,
    /// Total allocated memory
    allocated: usize,
    /// Maximum allowed memory allocation
    max_memory: usize,
}

/// A segment of memory in the address space
#[derive(Debug, Clone)]
struct MemorySegment {
    /// Base address of the segment
    base: u64,
    /// Size of the segment (validated to prevent overflow)
    size: usize,
    /// Permissions for this segment
    permissions: PagePermissions,
    /// Whether this segment is shared
    #[allow(dead_code)] // Will be used when implementing shared memory
    shared: bool,
}

/// Constants for memory safety
const MAX_SEGMENT_SIZE: usize = 1024 * 1024 * 1024; // 1GB max per segment
const MIN_SEGMENT_SIZE: usize = 4096; // 4KB minimum page size
const MAX_ADDRESS: u64 = 0x7FFF_FFFF_FFFF_F000; // Leave room for overflow checks
const NULL_PAGE_SIZE: u64 = 0x1000; // Protect first 4KB

impl MemorySegment {
    /// Check if this segment is shared between processes
    #[allow(dead_code)] // Will be used when implementing shared memory
    fn is_shared(&self) -> bool {
        self.shared
    }
    
    /// Create a new memory segment with security validation
    fn new(base: u64, size: usize, permissions: PagePermissions, shared: bool) -> ZkVmResult<Self> {
        // Validate segment size bounds
        if size == 0 {
            return Err(ZkVmError::MemoryError("Segment size cannot be zero".into()));
        }
        if size < MIN_SEGMENT_SIZE {
            return Err(ZkVmError::MemoryError(
                format!("Segment size {} too small, minimum is {}", size, MIN_SEGMENT_SIZE)
            ));
        }
        if size > MAX_SEGMENT_SIZE {
            return Err(ZkVmError::MemoryError(
                format!("Segment size {} exceeds maximum {}", size, MAX_SEGMENT_SIZE)
            ));
        }
        
        // Validate base address
        if base < NULL_PAGE_SIZE {
            return Err(ZkVmError::MemoryError(
                "Cannot allocate in null page region".into()
            ));
        }
        if base > MAX_ADDRESS {
            return Err(ZkVmError::MemoryError(
                "Base address exceeds maximum allowed address".into()
            ));
        }
        
        // Check for integer overflow in end address calculation
        let end_address = base.checked_add(size as u64)
            .ok_or_else(|| ZkVmError::MemoryError(
                "Integer overflow in segment end address calculation".into()
            ))?;
        
        if end_address > MAX_ADDRESS {
            return Err(ZkVmError::MemoryError(
                "Segment end address exceeds maximum allowed address".into()
            ));
        }
        
        Ok(Self {
            base,
            size,
            permissions,
            shared,
        })
    }
    
    /// Create a shared memory segment
    #[allow(dead_code)] // Will be used when implementing shared memory
    fn new_shared(base: u64, size: usize, permissions: PagePermissions) -> ZkVmResult<Self> {
        Self::new(base, size, permissions, true)
    }
    
    /// Create a private memory segment
    #[allow(dead_code)] // Will be used when implementing private memory allocation
    fn new_private(base: u64, size: usize, permissions: PagePermissions) -> ZkVmResult<Self> {
        Self::new(base, size, permissions, false)
    }
    
    /// Get the end address of this segment (exclusive)
    fn end_address(&self) -> ZkVmResult<u64> {
        self.base.checked_add(self.size as u64)
            .ok_or_else(|| ZkVmError::MemoryError(
                "Integer overflow in segment end address calculation".into()
            ))
    }
    
    /// Check if this segment contains the given address
    fn contains_address(&self, addr: u64) -> ZkVmResult<bool> {
        let end = self.end_address()?;
        Ok(addr >= self.base && addr < end)
    }
    
    /// Check if this segment overlaps with another segment
    fn overlaps_with(&self, other: &MemorySegment) -> ZkVmResult<bool> {
        let self_end = self.end_address()?;
        let other_end = other.end_address()?;
        
        // Two segments overlap if:
        // self.base < other_end && other.base < self_end
        Ok(self.base < other_end && other.base < self_end)
    }
}

impl Executor {
    /// Create a new executor instance
    pub fn new(memory_limit: usize) -> ZkVmResult<Self> {
        // Validate memory limit
        if memory_limit == 0 {
            return Err(ZkVmError::MemoryError("Memory limit cannot be zero".into()));
        }
        if memory_limit > MAX_SEGMENT_SIZE * 100 { // Allow up to 100GB total
            return Err(ZkVmError::MemoryError(
                "Memory limit exceeds maximum allowed".into()
            ));
        }
        
        Ok(Self {
            address_space: Arc::new(RwLock::new(AddressSpace {
                segments: BTreeMap::new(),
                allocated: 0,
                max_memory: memory_limit,
            })),
            state: ExecutorState {
                pc: 0,
                sp: 0,
                bp: 0,
                flags: 0,
                registers: [0; 16],
            },
            flags: ExecutionFlags {
                enable_jit: true,
                memory_limit,
                time_limit: 5000, // 5 seconds default
            },
        })
    }
    
    /// Allocate a new memory segment with comprehensive security checks
    pub fn allocate_segment(&mut self, size: usize, permissions: PagePermissions) -> ZkVmResult<u64> {
        let mut address_space = self.address_space.write();
        
        // Validate size parameter
        if size == 0 {
            return Err(ZkVmError::MemoryError("Cannot allocate zero-sized segment".into()));
        }
        if size > MAX_SEGMENT_SIZE {
            return Err(ZkVmError::MemoryError(
                format!("Segment size {} exceeds maximum {}", size, MAX_SEGMENT_SIZE)
            ));
        }
        
        // Check memory limits with overflow protection
        let new_allocated = address_space.allocated.checked_add(size)
            .ok_or_else(|| ZkVmError::MemoryError(
                "Integer overflow in total memory calculation".into()
            ))?;
        
        if new_allocated > address_space.max_memory {
            return Err(ZkVmError::MemoryError(
                format!(
                    "Memory limit exceeded: {} + {} > {}",
                    address_space.allocated, size, address_space.max_memory
                )
            ));
        }
        
        // Find a free address range
        let base = self.find_free_address_range(&address_space, size)?;
        
        // Create new segment with validation
        let segment = MemorySegment::new(base, size, permissions, false)?;
        
        // Check for overlaps with existing segments
        for existing_segment in address_space.segments.values() {
            if segment.overlaps_with(existing_segment)? {
                return Err(ZkVmError::MemoryError(
                    format!(
                        "Segment overlap detected: new segment [{:#x}-{:#x}] overlaps with existing [{:#x}-{:#x}]",
                        segment.base,
                        segment.end_address()?,
                        existing_segment.base,
                        existing_segment.end_address()?
                    )
                ));
            }
        }
        
        // Insert the segment (BTreeMap keeps them sorted by base address)
        address_space.segments.insert(base, segment);
        address_space.allocated = new_allocated;
        
        Ok(base)
    }
    
    /// Find a free address range of the required size with overflow protection
    fn find_free_address_range(&self, address_space: &AddressSpace, size: usize) -> ZkVmResult<u64> {
        let mut base: u64 = NULL_PAGE_SIZE; // Start after null page
        let size_u64 = size as u64;
        
        // Validate size conversion
        if size_u64 as usize != size {
            return Err(ZkVmError::MemoryError(
                "Size value too large for address space".into()
            ));
        }
        
        // Check if we can fit the segment starting at base
        let check_fit = |candidate_base: u64| -> ZkVmResult<bool> {
            // Check for integer overflow in end address calculation
            let end_address = candidate_base.checked_add(size_u64)
                .ok_or_else(|| ZkVmError::MemoryError(
                    "Integer overflow in address range calculation".into()
                ))?;
            
            // Ensure we don't exceed maximum address
            if end_address > MAX_ADDRESS {
                return Ok(false);
            }
            
            Ok(true)
        };
        
        // Iterate through segments in sorted order (BTreeMap provides this)
        for (_, segment) in &address_space.segments {
            // Check if we can fit before this segment
            let required_end = base.checked_add(size_u64)
                .ok_or_else(|| ZkVmError::MemoryError(
                    "Integer overflow in address calculation".into()
                ))?;
            
            if required_end <= segment.base && check_fit(base)? {
                return Ok(base);
            }
            
            // Move base to after this segment
            let segment_end = segment.end_address()?;
            
            // Align to page boundary for better memory management
            let aligned_base = (segment_end + MIN_SEGMENT_SIZE as u64 - 1) 
                & !(MIN_SEGMENT_SIZE as u64 - 1);
            
            base = cmp::max(base, aligned_base);
        }
        
        // Check if we can fit at the final position
        if !check_fit(base)? {
            return Err(ZkVmError::MemoryError(
                "No suitable address range found for segment".into()
            ));
        }
        
        Ok(base)
    }
    
    /// Execute code at the given address
    pub fn execute(&mut self, entry_point: u64) -> ZkVmResult<()> {
        self.state.pc = entry_point;
        
        loop {
            // Fetch instruction
            let instruction = self.fetch_instruction()?;
            
            // Decode instruction
            let decoded = self.decode_instruction(instruction)?;
            
            // Execute instruction
            self.execute_instruction(decoded)?;
            
            // Check execution limits
            self.check_limits()?;
        }
    }
    
    /// Fetch the next instruction with bounds checking
    fn fetch_instruction(&self) -> ZkVmResult<u32> {
        let address_space = self.address_space.read();
        let pc = self.state.pc;
        
        // Validate PC is not in null page
        if pc < NULL_PAGE_SIZE {
            return Err(ZkVmError::MemoryError(
                "Attempted to execute from null page".into()
            ));
        }
        
        // Find the segment containing the current PC using efficient lookup
        // Find the largest base address <= pc
        if let Some((_, segment)) = address_space.segments.range(..=pc).next_back() {
            // Check if PC is actually within this segment
            if segment.contains_address(pc)? {
                // Check execute permission
                if !segment.permissions.execute {
                    return Err(ZkVmError::MemoryError(
                        format!("No execute permission at address 0x{:x}", pc)
                    ));
                }
                
                // Ensure we can read a full 4-byte instruction without overflow
                let instruction_end = pc.checked_add(4)
                    .ok_or_else(|| ZkVmError::MemoryError(
                        "Integer overflow in instruction fetch".into()
                    ))?;
                
                if !segment.contains_address(instruction_end - 1)? {
                    return Err(ZkVmError::MemoryError(
                        format!("Instruction at 0x{:x} crosses segment boundary", pc)
                    ));
                }
                
                // For now, return a NOP instruction (0x00000000)
                // In a real implementation, this would read from actual memory
                return Ok(0x00000000);
            }
        }
        
        Err(ZkVmError::MemoryError(
            format!("Invalid instruction address: 0x{:x}", pc)
        ))
    }
    
    /// Decode an instruction
    fn decode_instruction(&self, instruction: u32) -> ZkVmResult<DecodedInstruction> {
        // Simple instruction format: [opcode:8][reg1:4][reg2:4][reg3:4][immediate:12]
        let opcode = (instruction >> 24) & 0xFF;
        let reg1 = ((instruction >> 20) & 0xF) as u8;
        let reg2 = ((instruction >> 16) & 0xF) as u8;
        let reg3 = ((instruction >> 12) & 0xF) as u8;
        let immediate = (instruction & 0xFFF) as u16;
        
        let instruction_type = match opcode {
            0x00 => InstructionType::Nop,
            0x01 => InstructionType::Load { reg: reg1, addr: immediate as u32 },
            0x02 => InstructionType::Store { reg: reg1, addr: immediate as u32 },
            0x03 => InstructionType::Add { dest: reg1, src1: reg2, src2: reg3 },
            0x04 => InstructionType::Sub { dest: reg1, src1: reg2, src2: reg3 },
            0x05 => InstructionType::Jump { addr: immediate as u32 },
            0x06 => InstructionType::JumpIf { condition: reg1, addr: immediate as u32 },
            0xFF => InstructionType::Halt,
            _ => return Err(ZkVmError::ExecutionError(
                format!("Unknown opcode: 0x{:02x}", opcode)
            )),
        };
        
        Ok(DecodedInstruction {
            instruction_type,
            raw: instruction,
        })
    }
    
    /// Execute a decoded instruction
    fn execute_instruction(&mut self, instruction: DecodedInstruction) -> ZkVmResult<()> {
        match instruction.instruction_type {
            InstructionType::Nop => {
                // Do nothing, just advance PC
                self.state.pc += 4;
            }
            InstructionType::Load { reg, addr } => {
                // Load from memory address into register
                if reg < 16 {
                    // Read from memory at the specified address
                    let value = self.read_memory(addr)?;
                    self.state.registers[reg as usize] = value;
                    self.state.pc += 4;
                } else {
                    return Err(ZkVmError::ExecutionError(
                        format!("Invalid register: R{}", reg)
                    ));
                }
            }
            InstructionType::Store { reg, addr } => {
                // Store register value to memory address
                if reg < 16 {
                    // Write register value to memory at the specified address
                    let value = self.state.registers[reg as usize];
                    self.write_memory(addr, value)?;
                    self.state.pc += 4;
                } else {
                    return Err(ZkVmError::ExecutionError(
                        format!("Invalid register: R{}", reg)
                    ));
                }
            }
            InstructionType::Add { dest, src1, src2 } => {
                if dest < 16 && src1 < 16 && src2 < 16 {
                    // In a real implementation, this would perform register arithmetic
                    self.state.pc += 4;
                } else {
                    return Err(ZkVmError::ExecutionError(
                        "Invalid register in ADD instruction".into()
                    ));
                }
            }
            InstructionType::Sub { dest, src1, src2 } => {
                if dest < 16 && src1 < 16 && src2 < 16 {
                    // In a real implementation, this would perform register arithmetic
                    self.state.pc += 4;
                } else {
                    return Err(ZkVmError::ExecutionError(
                        "Invalid register in SUB instruction".into()
                    ));
                }
            }
            InstructionType::Jump { addr } => {
                self.state.pc = addr as u64;
            }
            InstructionType::JumpIf { condition, addr } => {
                if condition < 16 {
                    // Jump to addr if condition register is non-zero
                    if self.state.registers[condition as usize] != 0 {
                        self.state.pc = addr as u64;
                    } else {
                        self.state.pc += 4;
                    }
                } else {
                    return Err(ZkVmError::ExecutionError(
                        format!("Invalid register: R{}", condition)
                    ));
                }
            }
            InstructionType::Halt => {
                return Err(ZkVmError::ExecutionError("Halt instruction executed".into()));
            }
        }
        
        Ok(())
    }
    
    /// Read a 32-bit value from memory with bounds checking
    fn read_memory(&self, addr: u32) -> ZkVmResult<u32> {
        let address_space = self.address_space.read();
        let addr_u64 = addr as u64;
        
        // Validate address is not in null page
        if addr_u64 < NULL_PAGE_SIZE {
            return Err(ZkVmError::MemoryError(
                "Attempted to read from null page".into()
            ));
        }
        
        // Find the segment containing this address using efficient lookup
        if let Some((_, segment)) = address_space.segments.range(..=addr_u64).next_back() {
            if segment.contains_address(addr_u64)? {
                // Check read permission
                if !segment.permissions.read {
                    return Err(ZkVmError::MemoryError(
                        format!("No read permission at address 0x{:x}", addr)
                    ));
                }
                
                // Ensure we can read a full 4-byte value without overflow
                let read_end = addr_u64.checked_add(4)
                    .ok_or_else(|| ZkVmError::MemoryError(
                        "Integer overflow in memory read".into()
                    ))?;
                
                if !segment.contains_address(read_end - 1)? {
                    return Err(ZkVmError::MemoryError(
                        format!("Read at 0x{:x} crosses segment boundary", addr)
                    ));
                }
                
                // In a real implementation, this would read from actual memory
                // For now, return a placeholder value
                return Ok(0);
            }
        }
        
        Err(ZkVmError::MemoryError(
            format!("Address 0x{:x} not mapped", addr)
        ))
    }
    
    /// Write a 32-bit value to memory with bounds checking
    fn write_memory(&mut self, addr: u32, _value: u32) -> ZkVmResult<()> {
        let address_space = self.address_space.read();
        let addr_u64 = addr as u64;
        
        // Validate address is not in null page
        if addr_u64 < NULL_PAGE_SIZE {
            return Err(ZkVmError::MemoryError(
                "Attempted to write to null page".into()
            ));
        }
        
        // Find the segment containing this address using efficient lookup
        if let Some((_, segment)) = address_space.segments.range(..=addr_u64).next_back() {
            if segment.contains_address(addr_u64)? {
                // Check write permission
                if !segment.permissions.write {
                    return Err(ZkVmError::MemoryError(
                        format!("No write permission at address 0x{:x}", addr)
                    ));
                }
                
                // Ensure we can write a full 4-byte value without overflow
                let write_end = addr_u64.checked_add(4)
                    .ok_or_else(|| ZkVmError::MemoryError(
                        "Integer overflow in memory write".into()
                    ))?;
                
                if !segment.contains_address(write_end - 1)? {
                    return Err(ZkVmError::MemoryError(
                        format!("Write at 0x{:x} crosses segment boundary", addr)
                    ));
                }
                
                // In a real implementation, this would write to actual memory
                // For now, just return success
                return Ok(());
            }
        }
        
        Err(ZkVmError::MemoryError(
            format!("Address 0x{:x} not mapped", addr)
        ))
    }
    
    /// Check execution limits and validate state
    fn check_limits(&self) -> ZkVmResult<()> {
        // Check if we've exceeded time limits
        // In a real implementation, this would track execution time
        
        let pc = self.state.pc;
        
        // Validate PC is not in null page
        if pc < NULL_PAGE_SIZE {
            return Err(ZkVmError::ExecutionError(
                "Program counter in null page region".into()
            ));
        }
        
        // Check if PC exceeds maximum address
        if pc > MAX_ADDRESS {
            return Err(ZkVmError::ExecutionError(
                format!("Program counter exceeds maximum address: 0x{:x}", pc)
            ));
        }
        
        // Check if PC is within valid executable memory range
        let address_space = self.address_space.read();
        
        // Use efficient lookup to find the segment containing PC
        if let Some((_, segment)) = address_space.segments.range(..=pc).next_back() {
            if let Ok(contains) = segment.contains_address(pc) {
                if contains && segment.permissions.execute {
                    return Ok(());
                }
            }
        }
        
        Err(ZkVmError::ExecutionError(
            format!("Program counter out of bounds or no execute permission: 0x{:x}", pc)
        ))
    }
    
    /// Add a method to validate memory state integrity
    pub fn validate_memory_integrity(&self) -> ZkVmResult<()> {
        let address_space = self.address_space.read();
        
        // Verify total allocated memory matches sum of segments
        let calculated_total: usize = address_space.segments.values()
            .map(|seg| seg.size)
            .try_fold(0usize, |acc, size| acc.checked_add(size))
            .ok_or_else(|| ZkVmError::MemoryError(
                "Integer overflow in total memory calculation".into()
            ))?;
        
        if calculated_total != address_space.allocated {
            return Err(ZkVmError::MemoryError(
                format!(
                    "Memory accounting mismatch: allocated={}, calculated={}",
                    address_space.allocated, calculated_total
                )
            ));
        }
        
        // Verify no overlapping segments
        let mut segments: Vec<_> = address_space.segments.values().collect();
        segments.sort_by_key(|seg| seg.base);
        
        for window in segments.windows(2) {
            let seg1 = window[0];
            let seg2 = window[1];
            
            if seg1.overlaps_with(seg2)? {
                return Err(ZkVmError::MemoryError(
                    format!(
                        "Overlapping segments detected: [{:#x}-{:#x}] and [{:#x}-{:#x}]",
                        seg1.base, seg1.end_address()?,
                        seg2.base, seg2.end_address()?
                    )
                ));
            }
        }
        
        Ok(())
    }
    
    /// Deallocate a memory segment
    pub fn deallocate_segment(&mut self, base: u64) -> ZkVmResult<()> {
        let mut address_space = self.address_space.write();
        
        if let Some(segment) = address_space.segments.remove(&base) {
            // Use checked subtraction to prevent underflow
            address_space.allocated = address_space.allocated.checked_sub(segment.size)
                .ok_or_else(|| ZkVmError::MemoryError(
                    "Integer underflow in memory deallocation".into()
                ))?;
            Ok(())
        } else {
            Err(ZkVmError::MemoryError(
                format!("No segment found at base address 0x{:x}", base)
            ))
        }
    }
}

/// Represents a decoded instruction
#[derive(Debug)]
struct DecodedInstruction {
    /// The type and parameters of the instruction
    instruction_type: InstructionType,
    /// Raw instruction word
    #[allow(dead_code)] // Will be used when implementing instruction debugging
    raw: u32,
}

impl DecodedInstruction {
    /// Get the opcode from raw instruction
    #[allow(dead_code)] // Will be used when implementing instruction debugging
    fn opcode(&self) -> u8 {
        ((self.raw >> 24) & 0xFF) as u8
    }
    
    /// Get the first register field
    #[allow(dead_code)] // Will be used when implementing instruction debugging
    fn reg1(&self) -> u8 {
        ((self.raw >> 16) & 0xFF) as u8
    }
    
    /// Get the second register field
    #[allow(dead_code)] // Will be used when implementing instruction debugging
    fn reg2(&self) -> u8 {
        ((self.raw >> 8) & 0xFF) as u8
    }
    
    /// Get the immediate value
    #[allow(dead_code)] // Will be used when implementing instruction debugging
    fn immediate(&self) -> u16 {
        (self.raw & 0xFFFF) as u16
    }
    
    /// Check if this is a privileged instruction
    #[allow(dead_code)] // Will be used when implementing privilege checks
    fn is_privileged(&self) -> bool {
        // Certain opcodes require elevated privileges
        matches!(self.opcode(), 0xF0..=0xFF)
    }
}

/// Types of instructions supported by the ZKVM
#[derive(Debug, Clone)]
enum InstructionType {
    /// No operation
    Nop,
    /// Load from memory to register
    Load { reg: u8, addr: u32 },
    /// Store from register to memory
    Store { reg: u8, addr: u32 },
    /// Add two registers
    Add { dest: u8, src1: u8, src2: u8 },
    /// Subtract two registers
    Sub { dest: u8, src1: u8, src2: u8 },
    /// Unconditional jump
    Jump { addr: u32 },
    /// Conditional jump
    JumpIf { condition: u8, addr: u32 },
    /// Halt execution
    Halt,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_executor_creation() {
        let executor = Executor::new(1024 * 1024).unwrap(); // 1MB limit
        assert_eq!(executor.flags.memory_limit, 1024 * 1024);
    }
    
    #[test]
    fn test_executor_creation_invalid_limits() {
        // Test zero memory limit
        assert!(Executor::new(0).is_err());
        
        // Test extremely large memory limit
        assert!(Executor::new(usize::MAX).is_err());
    }
    
    #[test]
    fn test_segment_allocation() {
        let mut executor = Executor::new(1024 * 1024).unwrap();
        let perms = PagePermissions {
            read: true,
            write: true,
            execute: false,
        };
        
        let base = executor.allocate_segment(4096, perms).unwrap();
        assert!(base >= NULL_PAGE_SIZE); // Should be after null page
        
        // Try to allocate beyond limit
        let result = executor.allocate_segment(2 * 1024 * 1024, perms);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_integer_overflow_protection() {
        let mut executor = Executor::new(1024 * 1024).unwrap();
        let perms = PagePermissions {
            read: true,
            write: true,
            execute: false,
        };
        
        // Test allocation with size that would cause overflow
        let result = executor.allocate_segment(MAX_SEGMENT_SIZE + 1, perms);
        assert!(result.is_err());
        
        // Test zero-size allocation
        let result = executor.allocate_segment(0, perms);
        assert!(result.is_err());
        
        // Test allocation that would exceed memory limit via integer overflow
        let result = executor.allocate_segment(usize::MAX, perms);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_memory_segment_overlap_detection() {
        let mut executor = Executor::new(1024 * 1024).unwrap();
        let perms = PagePermissions {
            read: true,
            write: true,
            execute: false,
        };
        
        // Allocate first segment
        let _base1 = executor.allocate_segment(4096, perms).unwrap();
        
        // Try to manually create overlapping segment (this should be prevented by allocation logic)
        let address_space = executor.address_space.read();
        let segments: Vec<_> = address_space.segments.values().collect();
        assert_eq!(segments.len(), 1);
        
        // Verify no overlaps exist
        for (i, seg1) in segments.iter().enumerate() {
            for (j, seg2) in segments.iter().enumerate() {
                if i != j {
                    assert!(!seg1.overlaps_with(seg2).unwrap());
                }
            }
        }
        drop(address_space);
        
        // Allocate second segment - should not overlap
        let _base2 = executor.allocate_segment(4096, perms).unwrap();
        
        // Verify memory integrity
        executor.validate_memory_integrity().unwrap();
    }
    
    #[test]
    fn test_memory_bounds_checking() {
        let executor = Executor::new(1024 * 1024).unwrap();
        
        // Test reading from null page
        let result = executor.read_memory(0x100); // Within null page
        assert!(result.is_err());
        
        // Test reading from unmapped memory
        let result = executor.read_memory(0x50000000);
        assert!(result.is_err());
        
        // Test program counter validation
        let mut executor_mut = executor;
        executor_mut.state.pc = 0x500; // In null page
        let result = executor_mut.check_limits();
        assert!(result.is_err());
        
        executor_mut.state.pc = MAX_ADDRESS + 1; // Beyond max address
        let result = executor_mut.check_limits();
        assert!(result.is_err());
    }
    
    #[test]
    fn test_memory_segment_validation() {
        // Test segment creation with invalid parameters
        let result = MemorySegment::new(0x500, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false); // Base in null page
        assert!(result.is_err());
        
        let result = MemorySegment::new(MAX_ADDRESS + 1, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false); // Base beyond max
        assert!(result.is_err());
        
        let result = MemorySegment::new(0x10000, 0, PagePermissions {
            read: true, write: false, execute: false
        }, false); // Zero size
        assert!(result.is_err());
        
        let result = MemorySegment::new(0x10000, MAX_SEGMENT_SIZE + 1, PagePermissions {
            read: true, write: false, execute: false
        }, false); // Too large
        assert!(result.is_err());
        
        // Test segment that would overflow end address
        let result = MemorySegment::new(MAX_ADDRESS - 100, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_memory_accounting() {
        let mut executor = Executor::new(1024 * 1024).unwrap();
        let perms = PagePermissions {
            read: true,
            write: true,
            execute: false,
        };
        
        // Allocate multiple segments
        let _base1 = executor.allocate_segment(4096, perms).unwrap();
        let base2 = executor.allocate_segment(8192, perms).unwrap();
        let _base3 = executor.allocate_segment(16384, perms).unwrap();
        
        // Verify memory accounting
        executor.validate_memory_integrity().unwrap();
        
        let address_space = executor.address_space.read();
        assert_eq!(address_space.allocated, 4096 + 8192 + 16384);
        drop(address_space);
        
        // Deallocate one segment
        executor.deallocate_segment(base2).unwrap();
        
        // Verify accounting after deallocation
        executor.validate_memory_integrity().unwrap();
        
        let address_space = executor.address_space.read();
        assert_eq!(address_space.allocated, 4096 + 16384);
        assert_eq!(address_space.segments.len(), 2);
        assert!(!address_space.segments.contains_key(&base2));
    }
    
    #[test]
    fn test_memory_cross_boundary_access() {
        let mut executor = Executor::new(1024 * 1024).unwrap();
        let perms = PagePermissions {
            read: true,
            write: true,
            execute: true,
        };
        
        // Allocate a small segment
        let base = executor.allocate_segment(4096, perms).unwrap();
        
        // Test reading near the end of the segment
        let near_end = (base + 4096 - 4) as u32; // Last valid 4-byte read
        let result = executor.read_memory(near_end);
        assert!(result.is_ok());
        
        // Test reading that would cross segment boundary
        let cross_boundary = (base + 4096 - 2) as u32; // Would read 2 bytes past end
        let result = executor.read_memory(cross_boundary);
        assert!(result.is_err());
        
        // Test instruction fetch at boundary
        executor.state.pc = base + 4096 - 4; // Last valid instruction
        let result = executor.fetch_instruction();
        assert!(result.is_ok());
        
        executor.state.pc = base + 4096 - 2; // Would cross boundary
        let result = executor.fetch_instruction();
        assert!(result.is_err());
    }
    
    #[test]
    fn test_permission_enforcement() {
        let mut executor = Executor::new(1024 * 1024).unwrap();
        
        // Create segments with different permissions
        let read_only = PagePermissions { read: true, write: false, execute: false };
        let execute_only = PagePermissions { read: false, write: false, execute: true };
        let no_perms = PagePermissions { read: false, write: false, execute: false };
        
        let ro_base = executor.allocate_segment(4096, read_only).unwrap();
        let exec_base = executor.allocate_segment(4096, execute_only).unwrap();
        let no_base = executor.allocate_segment(4096, no_perms).unwrap();
        
        // Test read permissions
        let result = executor.read_memory(ro_base as u32);
        assert!(result.is_ok()); // Should work - has read permission
        
        let result = executor.read_memory(exec_base as u32);
        assert!(result.is_err()); // Should fail - no read permission
        
        let result = executor.read_memory(no_base as u32);
        assert!(result.is_err()); // Should fail - no read permission
        
        // Test write permissions
        let result = executor.write_memory(ro_base as u32, 0x12345678);
        assert!(result.is_err()); // Should fail - no write permission
        
        let result = executor.write_memory(exec_base as u32, 0x12345678);
        assert!(result.is_err()); // Should fail - no write permission
        
        // Test execute permissions
        executor.state.pc = exec_base;
        let result = executor.fetch_instruction();
        assert!(result.is_ok()); // Should work - has execute permission
        
        executor.state.pc = ro_base;
        let result = executor.fetch_instruction();
        assert!(result.is_err()); // Should fail - no execute permission
    }
    
    #[test]
    fn test_address_space_exhaustion() {
        let mut executor = Executor::new(1024 * 1024).unwrap(); // 1MB limit
        let perms = PagePermissions {
            read: true,
            write: true,
            execute: false,
        };
        
        // Fill up the address space
        let mut allocated_segments = Vec::new();
        let segment_size = 64 * 1024; // 64KB segments
        
        // Allocate until we hit the limit
        loop {
            match executor.allocate_segment(segment_size, perms) {
                Ok(base) => allocated_segments.push(base),
                Err(_) => break, // Hit the limit
            }
        }
        
        // Verify we actually hit the memory limit, not some other error
        let address_space = executor.address_space.read();
        assert!(address_space.allocated <= address_space.max_memory);
        assert!(address_space.allocated + segment_size > address_space.max_memory);
        
        // Verify memory integrity
        drop(address_space);
        executor.validate_memory_integrity().unwrap();
    }
    
    #[test] 
    fn test_segment_overlap_detection_comprehensive() {
        // Test the overlap detection logic directly
        // Use minimum segment size to satisfy validation
        let seg1 = MemorySegment::new(0x10000, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false).unwrap();
        
        // Non-overlapping segment (before)
        let seg2 = MemorySegment::new(0x5000, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false).unwrap();
        assert!(!seg1.overlaps_with(&seg2).unwrap());
        
        // Non-overlapping segment (after)  
        let seg3 = MemorySegment::new(0x20000, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false).unwrap();
        assert!(!seg1.overlaps_with(&seg3).unwrap());
        
        // Overlapping segment (partial overlap at start)
        // seg1: 0x10000 to 0x10000 + MIN_SEGMENT_SIZE
        // seg4: 0x8000 to 0x8000 + MIN_SEGMENT_SIZE * 2
        // Since MIN_SEGMENT_SIZE = 4096, seg4 goes from 0x8000 to 0x10000, just touching seg1
        let seg4 = MemorySegment::new(0xF000, MIN_SEGMENT_SIZE * 2, PagePermissions {
            read: true, write: false, execute: false
        }, false).unwrap();
        assert!(seg1.overlaps_with(&seg4).unwrap());
        
        // Overlapping segment (partial overlap at end) 
        // seg1: 0x10000 to 0x11000
        // seg5: overlaps by starting in the middle of seg1
        let seg5 = MemorySegment::new(0x10800, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false).unwrap();
        assert!(seg1.overlaps_with(&seg5).unwrap());
        
        // Adjacent segment (should not overlap)
        let seg6 = MemorySegment::new(0x10000 + MIN_SEGMENT_SIZE as u64, MIN_SEGMENT_SIZE, PagePermissions {
            read: true, write: false, execute: false
        }, false).unwrap();
        assert!(!seg1.overlaps_with(&seg6).unwrap());
        
        // Segment that completely contains seg1
        let seg7 = MemorySegment::new(0xF000, MIN_SEGMENT_SIZE * 3, PagePermissions {
            read: true, write: false, execute: false
        }, false).unwrap();
        assert!(seg1.overlaps_with(&seg7).unwrap());
    }
} 