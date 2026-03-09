with FBVBS.ABI;

package FBVBS.KCI
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;
   use type FBVBS.ABI.Verification_Record;

   procedure Initialize (State : out FBVBS.ABI.Verification_Record)
     with
       Post =>
         State.Approved_Module_Object_Id = 0
         and then State.Approved_Manifest_Object_Id = 0
         and then State.Approved_Generation = 0
         and then State.Intercepted_MSR_Count = 0;

   procedure Verify_Module
     (State              : in out FBVBS.ABI.Verification_Record;
      Module_Object_Id   : FBVBS.ABI.Handle;
      Manifest_Object_Id : FBVBS.ABI.Handle;
      Generation         : FBVBS.ABI.U64;
      Status             : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.Approved_Module_Object_Id = Module_Object_Id
             and then State.Approved_Manifest_Object_Id = Manifest_Object_Id
             and then State.Approved_Generation = Generation
          else
             State = State'Old);

   procedure Set_WX
     (State            : in out FBVBS.ABI.Verification_Record;
      Module_Object_Id : FBVBS.ABI.Handle;
      Writable         : Boolean;
      Executable       : Boolean;
      Status           : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State = State'Old
          else
             State = State'Old);

   procedure Pin_CR0
     (State    : in out FBVBS.ABI.Verification_Record;
      Pin_Mask : FBVBS.ABI.U64;
      Status   : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.Pinned_CR0_Mask = Pin_Mask
          else
             State = State'Old);

   procedure Pin_CR4
     (State    : in out FBVBS.ABI.Verification_Record;
      Pin_Mask : FBVBS.ABI.U64;
      Status   : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.Pinned_CR4_Mask = Pin_Mask
          else
             State = State'Old);

   procedure Intercept_MSR
     (State       : in out FBVBS.ABI.Verification_Record;
      MSR_Address : FBVBS.ABI.U32;
      Enable      : Boolean;
      Status      : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             (if Enable then
                 State.Intercepted_MSR_Count >= State'Old.Intercepted_MSR_Count
              else
                 State.Intercepted_MSR_Count <= State'Old.Intercepted_MSR_Count)
          else
             State = State'Old);
end FBVBS.KCI;
