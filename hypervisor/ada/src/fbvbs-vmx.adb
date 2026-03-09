with FBVBS.ABI;
with FBVBS.VM_Policy;

package body FBVBS.VMX
  with SPARK_Mode
is
   procedure Initialize (VCPU : out FBVBS.ABI.VCPU_Record) is
   begin
      VCPU :=
         (State                    => FBVBS.ABI.VCPU_Created,
          RIP                      => 0,
          RSP                      => 0,
          RFlags                   => 0,
          CR0                      => 0,
          CR3                      => 0,
          CR4                      => 0,
          Pending_Interrupt_Vector => 0,
          Interrupt_Pending        => False);
    end Initialize;

   procedure Start (VCPU : in out FBVBS.ABI.VCPU_Record) is
   begin
      if VCPU.State = FBVBS.ABI.VCPU_Created then
         VCPU.State := FBVBS.ABI.VCPU_Runnable;
      end if;
   end Start;

   procedure Inject_Interrupt
     (VCPU   : in out FBVBS.ABI.VCPU_Record;
      Vector : FBVBS.ABI.U32;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if (VCPU.State /= FBVBS.ABI.VCPU_Runnable and then VCPU.State /= FBVBS.ABI.VCPU_Blocked)
        or else Vector = 0
      then
         Status := FBVBS.ABI.Invalid_State;
      else
         VCPU.Pending_Interrupt_Vector := Vector;
         VCPU.Interrupt_Pending := True;
         if VCPU.State = FBVBS.ABI.VCPU_Blocked then
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
         end if;
         Status := FBVBS.ABI.OK;
      end if;
    end Inject_Interrupt;

   procedure Set_Register
     (VCPU        : in out FBVBS.ABI.VCPU_Record;
      Register_Id : FBVBS.ABI.U32;
      Value       : FBVBS.ABI.U64;
      Status      : out FBVBS.ABI.Status_Code)
   is
   begin
      if VCPU.State = FBVBS.ABI.VCPU_Running then
         Status := FBVBS.ABI.Invalid_State;
      else
         case Register_Id is
            when FBVBS.ABI.VM_Reg_RIP =>
               VCPU.RIP := Value;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_RSP =>
               VCPU.RSP := Value;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_RFLAGS =>
               VCPU.RFlags := Value;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_CR0 =>
               VCPU.CR0 := Value;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_CR3 =>
               Status := FBVBS.ABI.Permission_Denied;
            when FBVBS.ABI.VM_Reg_CR4 =>
               VCPU.CR4 := Value;
               Status := FBVBS.ABI.OK;
            when others =>
               Status := FBVBS.ABI.Invalid_Parameter;
         end case;
      end if;
   end Set_Register;

   procedure Get_Register
     (VCPU        : FBVBS.ABI.VCPU_Record;
      Register_Id : FBVBS.ABI.U32;
      Value       : out FBVBS.ABI.U64;
      Status      : out FBVBS.ABI.Status_Code)
   is
   begin
      Value := 0;
      if VCPU.State = FBVBS.ABI.VCPU_Running then
         Status := FBVBS.ABI.Invalid_State;
      else
         case Register_Id is
            when FBVBS.ABI.VM_Reg_RIP =>
               Value := VCPU.RIP;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_RSP =>
               Value := VCPU.RSP;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_RFLAGS =>
               Value := VCPU.RFlags;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_CR0 =>
               Value := VCPU.CR0;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_CR3 =>
               Value := VCPU.CR3;
               Status := FBVBS.ABI.OK;
            when FBVBS.ABI.VM_Reg_CR4 =>
               Value := VCPU.CR4;
               Status := FBVBS.ABI.OK;
            when others =>
               Status := FBVBS.ABI.Invalid_Parameter;
         end case;
      end if;
   end Get_Register;

    procedure Run
       (VCPU                 : in out FBVBS.ABI.VCPU_Record;
       Has_HLAT             : Boolean;
       Pinned_CR0_Mask      : FBVBS.ABI.U64;
       Pinned_CR4_Mask      : FBVBS.ABI.U64;
       Intercepted_MSRs     : FBVBS.ABI.U32;
       Mapped_Bytes         : FBVBS.ABI.U64;
      VCPU_Id              : FBVBS.ABI.U32;
       Result               : out FBVBS.ABI.VMX_Run_Result;
       Status               : out FBVBS.ABI.Status_Code)
    is
       Leaf_Exit : FBVBS.ABI.VMX_Leaf_Exit_Record :=
         (Exit_Reason            => FBVBS.ABI.No_Exit,
          CR_Number              => 0,
          MSR_Address            => 0,
          Port                   => 0,
          Access_Size            => 0,
          Is_Write               => False,
          Value                  => 0,
          Guest_Physical_Address => 0);
    begin
       Result :=
         (Exit_Reason            => FBVBS.ABI.No_Exit,
          Fault_Code             => 0,
          Detail0                => 0,
          Detail1                => 0,
          Interrupt_Vector       => 0,
          CR_Number              => 0,
          MSR_Address            => 0,
          Port                   => 0,
          Access_Size            => 0,
          Is_Write               => False,
          Value                  => 0,
          Guest_Physical_Address => 0);

      if not Has_HLAT then
          Status := FBVBS.ABI.Not_Supported_On_Platform;
          return;
      end if;

      if VCPU.State /= FBVBS.ABI.VCPU_Runnable then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

       VCPU.State := FBVBS.ABI.VCPU_Running;

       if VCPU.Interrupt_Pending then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_External_Interrupt;
          Leaf_Exit.Value := FBVBS.ABI.U64 (VCPU.Pending_Interrupt_Vector);
       elsif Pinned_CR0_Mask /= 0 and then (VCPU.CR0 and Pinned_CR0_Mask) /= Pinned_CR0_Mask then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_CR_Access;
          Leaf_Exit.CR_Number := 0;
          Leaf_Exit.Value := VCPU.CR0;
       elsif Pinned_CR4_Mask /= 0 and then (VCPU.CR4 and Pinned_CR4_Mask) /= Pinned_CR4_Mask then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_CR_Access;
          Leaf_Exit.CR_Number := 4;
          Leaf_Exit.Value := VCPU.CR4;
       elsif Intercepted_MSRs /= 0 then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_MSR_Access;
          Leaf_Exit.MSR_Address := Intercepted_MSRs;
       elsif Mapped_Bytes = 0 then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_EPT_Violation;
       elsif VCPU.RIP = FBVBS.ABI.Synthetic_Exit_RIP_PIO then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_PIO;
          Leaf_Exit.Port := FBVBS.ABI.U32 (VCPU.RSP and 16#FFFF#);
          Leaf_Exit.Access_Size := 4;
          Leaf_Exit.Is_Write := (VCPU.RFlags and 1) /= 0;
          Leaf_Exit.Value := VCPU.RFlags;
       elsif VCPU.RIP = FBVBS.ABI.Synthetic_Exit_RIP_MMIO then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_MMIO;
          Leaf_Exit.Guest_Physical_Address := VCPU.RSP;
          Leaf_Exit.Access_Size := 8;
          Leaf_Exit.Is_Write := (VCPU.RFlags and 1) /= 0;
          Leaf_Exit.Value := VCPU.RFlags;
       elsif VCPU.RIP = FBVBS.ABI.Synthetic_Exit_RIP_Shutdown then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_Shutdown;
       elsif VCPU.RIP = FBVBS.ABI.Synthetic_Exit_RIP_Fault then
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_Unclassified_Fault;
       else
          Leaf_Exit.Exit_Reason := FBVBS.ABI.Exit_Halt;
       end if;

       FBVBS.VM_Policy.Apply_Leaf_Exit (VCPU, VCPU_Id, Leaf_Exit, Result, Status);
    end Run;

   procedure Recover
     (VCPU   : in out FBVBS.ABI.VCPU_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if VCPU.State /= FBVBS.ABI.VCPU_Faulted then
         Status := FBVBS.ABI.Invalid_State;
      else
         VCPU.State := FBVBS.ABI.VCPU_Runnable;
         VCPU.Pending_Interrupt_Vector := 0;
         VCPU.Interrupt_Pending := False;
         VCPU.CR3 := 0;
         Status := FBVBS.ABI.OK;
      end if;
   end Recover;
end FBVBS.VMX;
