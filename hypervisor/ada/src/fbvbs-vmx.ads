with FBVBS.ABI;

package FBVBS.VMX
  with SPARK_Mode
is
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;
   use type FBVBS.ABI.VCPU_Record;
   use type FBVBS.ABI.VCPU_State;

   procedure Initialize (VCPU : out FBVBS.ABI.VCPU_Record)
     with Post => VCPU.State = FBVBS.ABI.VCPU_Created;

   procedure Start (VCPU : in out FBVBS.ABI.VCPU_Record)
     with
       Post =>
         (if VCPU.State'Old = FBVBS.ABI.VCPU_Created then
             VCPU.State = FBVBS.ABI.VCPU_Runnable
          else
             VCPU = VCPU'Old);

    procedure Inject_Interrupt
      (VCPU   : in out FBVBS.ABI.VCPU_Record;
       Vector : FBVBS.ABI.U32;
       Status : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
              VCPU.Interrupt_Pending
           else
              VCPU = VCPU'Old);

   procedure Set_Register
     (VCPU        : in out FBVBS.ABI.VCPU_Record;
      Register_Id : FBVBS.ABI.U32;
      Value       : FBVBS.ABI.U64;
      Status      : out FBVBS.ABI.Status_Code)
     with
       Post => (if Status /= FBVBS.ABI.OK then VCPU = VCPU'Old);

   procedure Get_Register
     (VCPU        : FBVBS.ABI.VCPU_Record;
      Register_Id : FBVBS.ABI.U32;
      Value       : out FBVBS.ABI.U64;
      Status      : out FBVBS.ABI.Status_Code);

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
     with
        Post =>
          (if Status /= FBVBS.ABI.OK then
              VCPU = VCPU'Old);

   procedure Recover
     (VCPU   : in out FBVBS.ABI.VCPU_Record;
      Status : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             VCPU.State = FBVBS.ABI.VCPU_Runnable
          else
             VCPU = VCPU'Old);
end FBVBS.VMX;
