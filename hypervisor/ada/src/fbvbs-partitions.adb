with FBVBS.ABI;

package body FBVBS.Partitions
  with SPARK_Mode
is
   use type FBVBS.ABI.Partition_Kind;
   use type FBVBS.ABI.Trusted_Service_Kind;

   procedure Initialize (Partition : out FBVBS.ABI.Partition_Descriptor) is
   begin
        Partition :=
          (In_Use            => False,
           Partition_Id      => 0,
           Kind              => FBVBS.ABI.Partition_None,
           State             => FBVBS.ABI.Created,
           Measurement_Epoch => 0,
           Service_Kind      => FBVBS.ABI.Service_None,
            Memory_Limit_Bytes => 0,
            Capability_Mask    => 0,
            Mapped_Bytes       => 0,
            Last_Fault_Code    => 0,
            Last_Source_Component => 0,
            Last_Fault_Detail0 => 0,
            Last_Fault_Detail1 => 0);
   end Initialize;

   procedure Create
     (Partition    : in out FBVBS.ABI.Partition_Descriptor;
      Partition_Id : FBVBS.ABI.U64;
      Status       : out FBVBS.ABI.Status_Code)
   is
   begin
      if Partition.In_Use then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

        Partition.In_Use       := True;
        Partition.Partition_Id := Partition_Id;
         Partition.Kind         := FBVBS.ABI.Partition_Trusted_Service;
         Partition.State        := FBVBS.ABI.Created;
          Partition.Service_Kind := FBVBS.ABI.Service_None;
          Partition.Memory_Limit_Bytes := 0;
          Partition.Capability_Mask := 0;
          Partition.Mapped_Bytes := 0;
          Partition.Last_Fault_Code := 0;
          Partition.Last_Source_Component := 0;
          Partition.Last_Fault_Detail0 := 0;
          Partition.Last_Fault_Detail1 := 0;
          Status                 := FBVBS.ABI.OK;
     end Create;

   procedure Create_Trusted_Service
     (Partition             : in out FBVBS.ABI.Partition_Descriptor;
      Partition_Id          : FBVBS.ABI.U64;
      Requested_VCPU_Count  : FBVBS.ABI.U32;
      Memory_Limit_Bytes    : FBVBS.ABI.U64;
      Capability_Mask       : FBVBS.ABI.U64;
      Image_Object_Id       : FBVBS.ABI.Handle;
      Create_Flags          : FBVBS.ABI.U32;
      Status                : out FBVBS.ABI.Status_Code)
   is
   begin
      if Partition.In_Use then
         Status := FBVBS.ABI.Invalid_State;
      elsif Partition_Id = 0 or else Requested_VCPU_Count = 0 or else Requested_VCPU_Count > 252 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Image_Object_Id = 0 or else Create_Flags /= 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Partition.In_Use := True;
         Partition.Partition_Id := Partition_Id;
         Partition.Kind := FBVBS.ABI.Partition_Trusted_Service;
         Partition.State := FBVBS.ABI.Created;
         Partition.Measurement_Epoch := 0;
         Partition.Service_Kind := FBVBS.ABI.Service_None;
         Partition.Memory_Limit_Bytes := Memory_Limit_Bytes;
         Partition.Capability_Mask := Capability_Mask;
         Partition.Mapped_Bytes := 0;
         Partition.Last_Fault_Code := 0;
         Partition.Last_Source_Component := 0;
         Partition.Last_Fault_Detail0 := 0;
         Partition.Last_Fault_Detail1 := 0;
         Status := FBVBS.ABI.OK;
      end if;
   end Create_Trusted_Service;

   procedure Bootstrap_FreeBSD_Host
     (Partition : in out FBVBS.ABI.Partition_Descriptor;
      Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if Partition.In_Use then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

      Partition.In_Use       := True;
      Partition.Partition_Id := 1;
       Partition.Kind         := FBVBS.ABI.Partition_FreeBSD_Host;
       Partition.State        := FBVBS.ABI.Runnable;
        Partition.Service_Kind := FBVBS.ABI.Service_None;
        Partition.Memory_Limit_Bytes := 0;
        Partition.Capability_Mask := 0;
        Partition.Mapped_Bytes := 0;
        Partition.Last_Fault_Code := 0;
        Partition.Last_Source_Component := 0;
        Partition.Last_Fault_Detail0 := 0;
        Partition.Last_Fault_Detail1 := 0;
        Status                 := FBVBS.ABI.OK;
    end Bootstrap_FreeBSD_Host;

   procedure Validate_Create_Profile
     (Requested_VCPU_Count   : FBVBS.ABI.U32;
      Expected_VCPU_Count    : FBVBS.ABI.U32;
      Requested_Memory_Limit : FBVBS.ABI.U64;
      Expected_Memory_Limit  : FBVBS.ABI.U64;
      Requested_Capability   : FBVBS.ABI.U64;
      Expected_Capability    : FBVBS.ABI.U64;
      Status                 : out FBVBS.ABI.Status_Code)
   is
   begin
      if Requested_VCPU_Count /= Expected_VCPU_Count or else
        Requested_Memory_Limit /= Expected_Memory_Limit or else
        Requested_Capability /= Expected_Capability
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Validate_Create_Profile;

   procedure Validate_Load_Profile
     (Requested_Entry_IP    : FBVBS.ABI.U64;
      Expected_Entry_IP     : FBVBS.ABI.U64;
      Requested_Initial_SP  : FBVBS.ABI.U64;
      Expected_Initial_SP   : FBVBS.ABI.U64;
      Require_Explicit_Stack : Boolean;
      Status                : out FBVBS.ABI.Status_Code)
   is
   begin
      if (Requested_Entry_IP /= 0 and then Requested_Entry_IP /= Expected_Entry_IP) then
          Status := FBVBS.ABI.Measurement_Failed;
      elsif Require_Explicit_Stack then
         if Requested_Initial_SP = 0 then
            Status := FBVBS.ABI.Invalid_Parameter;
         else
            Status := FBVBS.ABI.OK;
         end if;
      elsif Requested_Initial_SP /= 0 and then Requested_Initial_SP /= Expected_Initial_SP then
         Status := FBVBS.ABI.Measurement_Failed;
       else
          Status := FBVBS.ABI.OK;
       end if;
   end Validate_Load_Profile;

    procedure Measure
      (Partition        : in out FBVBS.ABI.Partition_Descriptor;
       Approval_Present : Boolean;
       Status           : out FBVBS.ABI.Status_Code)
    is
    begin
       if not Partition.In_Use or else Partition.State /= FBVBS.ABI.Created then
          Status := FBVBS.ABI.Invalid_State;
          return;
       elsif not Approval_Present then
          Status := FBVBS.ABI.Signature_Invalid;
          return;
       end if;

       Partition.State             := FBVBS.ABI.Measured;
       Partition.Measurement_Epoch := Partition.Measurement_Epoch + 1;
       Status                      := FBVBS.ABI.OK;
    end Measure;

    procedure Get_Status
      (Partition : FBVBS.ABI.Partition_Descriptor;
       Result    : out FBVBS.ABI.Partition_Status_Record;
       Status    : out FBVBS.ABI.Status_Code)
    is
     begin
        Result := (State => FBVBS.ABI.Created, Measurement_Epoch => 0);
        if not Partition.In_Use then
           Status := FBVBS.ABI.Not_Found;
       else
          Result.State := Partition.State;
          Result.Measurement_Epoch := Partition.Measurement_Epoch;
           Status := FBVBS.ABI.OK;
        end if;
     end Get_Status;

   procedure Get_Fault_Info
     (Partition : FBVBS.ABI.Partition_Descriptor;
      Result    : out FBVBS.ABI.Fault_Info_Record;
      Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      Result :=
        (Fault_Code       => 0,
         Source_Component => 0,
         Fault_Detail0    => 0,
         Fault_Detail1    => 0);
      if not Partition.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif Partition.State /= FBVBS.ABI.Faulted then
         Status := FBVBS.ABI.Invalid_State;
      else
         Result.Fault_Code := Partition.Last_Fault_Code;
         Result.Source_Component := Partition.Last_Source_Component;
         Result.Fault_Detail0 := Partition.Last_Fault_Detail0;
         Result.Fault_Detail1 := Partition.Last_Fault_Detail1;
         Status := FBVBS.ABI.OK;
      end if;
   end Get_Fault_Info;

    procedure Load
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else Partition.State /= FBVBS.ABI.Measured then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

      Partition.State := FBVBS.ABI.Loaded;
      Status          := FBVBS.ABI.OK;
   end Load;

   procedure Start
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else Partition.State /= FBVBS.ABI.Loaded then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

       Partition.State := FBVBS.ABI.Runnable;
       Status          := FBVBS.ABI.OK;
   end Start;

   procedure Quiesce
     (Partition : in out FBVBS.ABI.Partition_Descriptor;
      Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else
        (Partition.State /= FBVBS.ABI.Runnable and then Partition.State /= FBVBS.ABI.Running)
      then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

      Partition.State := FBVBS.ABI.Quiesced;
      Status := FBVBS.ABI.OK;
   end Quiesce;

    procedure Resume
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else Partition.State /= FBVBS.ABI.Quiesced then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

       Partition.State := FBVBS.ABI.Runnable;
       Status := FBVBS.ABI.OK;
    end Resume;

    procedure Refresh_VM_State
      (Partition                : in out FBVBS.ABI.Partition_Descriptor;
       Any_Running              : Boolean;
       Any_Runnable_Or_Blocked  : Boolean;
       Any_Faulted              : Boolean;
       Status                   : out FBVBS.ABI.Status_Code)
    is
    begin
       if not Partition.In_Use or else Partition.Kind /= FBVBS.ABI.Partition_Guest_VM or else
         Partition.State = FBVBS.ABI.Quiesced or else
         Partition.State = FBVBS.ABI.Destroyed
       then
          Status := FBVBS.ABI.Invalid_State;
       elsif Any_Faulted then
          Partition.State := FBVBS.ABI.Faulted;
          Status := FBVBS.ABI.OK;
       elsif Any_Running then
          Partition.State := FBVBS.ABI.Running;
          Status := FBVBS.ABI.OK;
       elsif Any_Runnable_Or_Blocked then
          Partition.State := FBVBS.ABI.Runnable;
          Status := FBVBS.ABI.OK;
       else
          Status := FBVBS.ABI.Invalid_State;
       end if;
    end Refresh_VM_State;

    procedure Fault
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Status    : out FBVBS.ABI.Status_Code)
   is
     begin
        if not Partition.In_Use or else
          (Partition.State /= FBVBS.ABI.Runnable and then
           Partition.State /= FBVBS.ABI.Running and then
           Partition.State /= FBVBS.ABI.Quiesced)
      then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

       Partition.State := FBVBS.ABI.Faulted;
       Partition.Last_Fault_Code := FBVBS.ABI.Fault_Code_Partition_Internal;
       Partition.Last_Source_Component := FBVBS.ABI.Source_Component_Microhypervisor;
       Partition.Last_Fault_Detail0 := 0;
       Partition.Last_Fault_Detail1 := 0;
       Status := FBVBS.ABI.OK;
    end Fault;

   procedure Fault
     (Partition        : in out FBVBS.ABI.Partition_Descriptor;
      Fault_Code       : FBVBS.ABI.U32;
      Source_Component : FBVBS.ABI.U32;
      Detail0          : FBVBS.ABI.U64;
      Detail1          : FBVBS.ABI.U64;
      Status           : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else
        (Partition.State /= FBVBS.ABI.Runnable and then
         Partition.State /= FBVBS.ABI.Running and then
         Partition.State /= FBVBS.ABI.Quiesced)
      then
         Status := FBVBS.ABI.Invalid_State;
      elsif Fault_Code = 0 or else Source_Component = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Partition.State := FBVBS.ABI.Faulted;
         Partition.Last_Fault_Code := Fault_Code;
         Partition.Last_Source_Component := Source_Component;
         Partition.Last_Fault_Detail0 := Detail0;
         Partition.Last_Fault_Detail1 := Detail1;
         Status := FBVBS.ABI.OK;
      end if;
   end Fault;

   procedure Recover
     (Partition : in out FBVBS.ABI.Partition_Descriptor;
      Has_Image : Boolean;
      Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else Partition.State /= FBVBS.ABI.Faulted then
         Status := FBVBS.ABI.Invalid_State;
      elsif not Has_Image then
         Status := FBVBS.ABI.Measurement_Failed;
       else
          Partition.Measurement_Epoch := Partition.Measurement_Epoch + 1;
          Partition.State := FBVBS.ABI.Runnable;
          Partition.Last_Fault_Code := 0;
          Partition.Last_Source_Component := 0;
          Partition.Last_Fault_Detail0 := 0;
          Partition.Last_Fault_Detail1 := 0;
          Status := FBVBS.ABI.OK;
       end if;
    end Recover;

   procedure Destroy
     (Partition : in out FBVBS.ABI.Partition_Descriptor;
      Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif Partition.Kind = FBVBS.ABI.Partition_Guest_VM then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Partition.State = FBVBS.ABI.Destroyed then
         Status := FBVBS.ABI.Invalid_State;
      else
         Partition.State := FBVBS.ABI.Destroyed;
         Partition.Mapped_Bytes := 0;
         Status := FBVBS.ABI.OK;
      end if;
   end Destroy;

   procedure Bind_Service
     (Partition    : in out FBVBS.ABI.Partition_Descriptor;
      Service_Kind : FBVBS.ABI.Trusted_Service_Kind;
      Status       : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else Service_Kind = FBVBS.ABI.Service_None then
         Status := FBVBS.ABI.Invalid_State;
      elsif Partition.Kind /= FBVBS.ABI.Partition_Trusted_Service or else
        Partition.State /= FBVBS.ABI.Measured
      then
         Status := FBVBS.ABI.Invalid_State;
      elsif Partition.Service_Kind = FBVBS.ABI.Service_None then
         Partition.Service_Kind := Service_Kind;
         Status := FBVBS.ABI.OK;
      elsif Partition.Service_Kind /= Service_Kind then
         Status := FBVBS.ABI.Invalid_Caller;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Bind_Service;
end FBVBS.Partitions;
