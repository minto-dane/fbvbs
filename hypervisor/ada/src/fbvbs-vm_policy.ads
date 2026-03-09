with FBVBS.ABI;

package FBVBS.VM_Policy
  with SPARK_Mode
is
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.VCPU_State;
   use type FBVBS.ABI.VM_Exit_Reason;

   procedure Apply_Leaf_Exit
      (VCPU      : in out FBVBS.ABI.VCPU_Record;
       VCPU_Id   : FBVBS.ABI.U32;
       Leaf_Exit : FBVBS.ABI.VMX_Leaf_Exit_Record;
       Result    : out FBVBS.ABI.VMX_Run_Result;
       Status    : out FBVBS.ABI.Status_Code)
      with
        Post =>
          (if Status = FBVBS.ABI.OK then
              Result.Exit_Reason = Leaf_Exit.Exit_Reason)
          and then
          (if Status = FBVBS.ABI.OK
             and then Leaf_Exit.Exit_Reason = FBVBS.ABI.Exit_External_Interrupt
           then
              VCPU.State = FBVBS.ABI.VCPU_Runnable
              and then not VCPU.Interrupt_Pending
           else
              True)
          and then
          (if Status = FBVBS.ABI.OK
             and then Leaf_Exit.Exit_Reason = FBVBS.ABI.Exit_Halt
           then
              (VCPU.State = FBVBS.ABI.VCPU_Blocked)
           else
              True)
          and then
          (if Status = FBVBS.ABI.OK
             and then Leaf_Exit.Exit_Reason = FBVBS.ABI.Exit_Unclassified_Fault
           then
              (VCPU.State = FBVBS.ABI.VCPU_Faulted)
           else
              True);
end FBVBS.VM_Policy;
