with FBVBS.ABI;

package body FBVBS.KCI
  with SPARK_Mode
is
   procedure Initialize (State : out FBVBS.ABI.Verification_Record) is
   begin
      State :=
        (Approved_Module_Object_Id   => 0,
         Approved_Manifest_Object_Id => 0,
         Approved_Generation         => 0,
         Pinned_CR0_Mask             => 0,
         Pinned_CR4_Mask             => 0,
         Intercepted_MSR_Count       => 0);
   end Initialize;

   procedure Verify_Module
     (State              : in out FBVBS.ABI.Verification_Record;
      Module_Object_Id   : FBVBS.ABI.Handle;
      Manifest_Object_Id : FBVBS.ABI.Handle;
      Generation         : FBVBS.ABI.U64;
      Status             : out FBVBS.ABI.Status_Code)
   is
   begin
      if Module_Object_Id = 0 or else Manifest_Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      if Generation /= FBVBS.ABI.KCI_Expected_Generation then
         Status := FBVBS.ABI.Generation_Mismatch;
         return;
      end if;

      State.Approved_Module_Object_Id := Module_Object_Id;
      State.Approved_Manifest_Object_Id := Manifest_Object_Id;
      State.Approved_Generation := Generation;
      Status := FBVBS.ABI.OK;
   end Verify_Module;

   procedure Set_WX
     (State            : in out FBVBS.ABI.Verification_Record;
      Module_Object_Id : FBVBS.ABI.Handle;
      Writable         : Boolean;
      Executable       : Boolean;
      Status           : out FBVBS.ABI.Status_Code)
   is
   begin
      if Module_Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif State.Approved_Module_Object_Id /= Module_Object_Id then
         Status := FBVBS.ABI.Invalid_State;
      elsif Writable or else not Executable then
         Status := FBVBS.ABI.Permission_Denied;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Set_WX;

   procedure Pin_CR0
     (State    : in out FBVBS.ABI.Verification_Record;
      Pin_Mask : FBVBS.ABI.U64;
      Status   : out FBVBS.ABI.Status_Code)
   is
   begin
      if Pin_Mask = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      State.Pinned_CR0_Mask := Pin_Mask;
      Status := FBVBS.ABI.OK;
   end Pin_CR0;

   procedure Pin_CR4
     (State    : in out FBVBS.ABI.Verification_Record;
      Pin_Mask : FBVBS.ABI.U64;
      Status   : out FBVBS.ABI.Status_Code)
   is
   begin
      if Pin_Mask = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      State.Pinned_CR4_Mask := Pin_Mask;
      Status := FBVBS.ABI.OK;
   end Pin_CR4;

   procedure Intercept_MSR
     (State       : in out FBVBS.ABI.Verification_Record;
      MSR_Address : FBVBS.ABI.U32;
      Enable      : Boolean;
      Status      : out FBVBS.ABI.Status_Code)
   is
   begin
      if MSR_Address /= FBVBS.ABI.KCI_MSR_EFER
        and then MSR_Address /= FBVBS.ABI.KCI_MSR_LSTAR
        and then MSR_Address /= FBVBS.ABI.KCI_MSR_SFMASK
      then
         Status := FBVBS.ABI.Permission_Denied;
         return;
      end if;

      if Enable then
         if State.Intercepted_MSR_Count = 3 then
            Status := FBVBS.ABI.Resource_Exhausted;
         else
            State.Intercepted_MSR_Count := State.Intercepted_MSR_Count + 1;
            Status := FBVBS.ABI.OK;
         end if;
      elsif State.Intercepted_MSR_Count = 0 then
         Status := FBVBS.ABI.OK;
      else
         State.Intercepted_MSR_Count := State.Intercepted_MSR_Count - 1;
         Status := FBVBS.ABI.OK;
      end if;
   end Intercept_MSR;
end FBVBS.KCI;
