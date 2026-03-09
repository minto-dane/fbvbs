with FBVBS.ABI;

package body FBVBS.VM_Policy
  with SPARK_Mode
is
   procedure Apply_Leaf_Exit
     (VCPU      : in out FBVBS.ABI.VCPU_Record;
      VCPU_Id   : FBVBS.ABI.U32;
      Leaf_Exit : FBVBS.ABI.VMX_Leaf_Exit_Record;
      Result    : out FBVBS.ABI.VMX_Run_Result;
      Status    : out FBVBS.ABI.Status_Code)
   is
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

      case Leaf_Exit.Exit_Reason is
         when FBVBS.ABI.Exit_External_Interrupt =>
            Result.Exit_Reason := FBVBS.ABI.Exit_External_Interrupt;
            Result.Interrupt_Vector := FBVBS.ABI.U32 (Leaf_Exit.Value);
            VCPU.Pending_Interrupt_Vector := 0;
            VCPU.Interrupt_Pending := False;
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_CR_Access =>
            Result.Exit_Reason := FBVBS.ABI.Exit_CR_Access;
            Result.CR_Number := Leaf_Exit.CR_Number;
            Result.Value := Leaf_Exit.Value;
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_PIO =>
            Result.Exit_Reason := FBVBS.ABI.Exit_PIO;
            Result.Port := Leaf_Exit.Port;
            Result.Access_Size := Leaf_Exit.Access_Size;
            Result.Is_Write := Leaf_Exit.Is_Write;
            Result.Value := Leaf_Exit.Value;
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_MMIO =>
            Result.Exit_Reason := FBVBS.ABI.Exit_MMIO;
            Result.Guest_Physical_Address := Leaf_Exit.Guest_Physical_Address;
            Result.Access_Size := Leaf_Exit.Access_Size;
            Result.Is_Write := Leaf_Exit.Is_Write;
            Result.Value := Leaf_Exit.Value;
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_MSR_Access =>
            Result.Exit_Reason := FBVBS.ABI.Exit_MSR_Access;
            Result.MSR_Address := Leaf_Exit.MSR_Address;
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_EPT_Violation =>
            Result.Exit_Reason := FBVBS.ABI.Exit_EPT_Violation;
            Result.Guest_Physical_Address := Leaf_Exit.Guest_Physical_Address;
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_Shutdown =>
            Result.Exit_Reason := FBVBS.ABI.Exit_Shutdown;
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_Unclassified_Fault =>
            Result.Exit_Reason := FBVBS.ABI.Exit_Unclassified_Fault;
            Result.Fault_Code := FBVBS.ABI.Fault_Code_VM_Exit_Unclassified;
            Result.Detail0 := FBVBS.ABI.U64 (VCPU_Id);
            Result.Detail1 := VCPU.RIP;
            VCPU.State := FBVBS.ABI.VCPU_Faulted;
            Status := FBVBS.ABI.OK;
         when FBVBS.ABI.Exit_Halt =>
            Result.Exit_Reason := FBVBS.ABI.Exit_Halt;
            VCPU.State := FBVBS.ABI.VCPU_Blocked;
            Status := FBVBS.ABI.OK;
         when others =>
            VCPU.State := FBVBS.ABI.VCPU_Runnable;
            Status := FBVBS.ABI.Invalid_State;
      end case;
   end Apply_Leaf_Exit;
end FBVBS.VM_Policy;
