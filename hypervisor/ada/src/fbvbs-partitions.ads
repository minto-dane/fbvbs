with FBVBS.ABI;

package FBVBS.Partitions
  with SPARK_Mode
is
   use type FBVBS.ABI.Partition_Descriptor;
   use type FBVBS.ABI.Partition_Kind;
   use type FBVBS.ABI.Partition_State;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.Trusted_Service_Kind;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;

   procedure Initialize (Partition : out FBVBS.ABI.Partition_Descriptor)
     with
        Post =>
           (not Partition.In_Use
            and then Partition.Partition_Id = 0
            and then Partition.Kind = FBVBS.ABI.Partition_None
            and then Partition.State = FBVBS.ABI.Created
            and then Partition.Measurement_Epoch = 0
            and then Partition.Memory_Limit_Bytes = 0
            and then Partition.Capability_Mask = 0
            and then Partition.Mapped_Bytes = 0);

   procedure Create
      (Partition    : in out FBVBS.ABI.Partition_Descriptor;
       Partition_Id : FBVBS.ABI.U64;
       Status       : out FBVBS.ABI.Status_Code)
     with
       Pre  => Partition_Id /= 0,
       Post =>
            ((if Status = FBVBS.ABI.OK then Partition.In_Use and then Partition.Partition_Id = Partition_Id
             else Partition = Partition'Old));

   procedure Create_Trusted_Service
     (Partition             : in out FBVBS.ABI.Partition_Descriptor;
      Partition_Id          : FBVBS.ABI.U64;
      Requested_VCPU_Count  : FBVBS.ABI.U32;
      Memory_Limit_Bytes    : FBVBS.ABI.U64;
      Capability_Mask       : FBVBS.ABI.U64;
      Image_Object_Id       : FBVBS.ABI.Handle;
      Create_Flags          : FBVBS.ABI.U32;
      Status                : out FBVBS.ABI.Status_Code)
     with
       Post =>
         ((if Status = FBVBS.ABI.OK then
               Partition.In_Use
               and then Partition.Partition_Id = Partition_Id
               and then Partition.Kind = FBVBS.ABI.Partition_Trusted_Service
               and then Partition.State = FBVBS.ABI.Created
           else
               Partition = Partition'Old));

   procedure Bootstrap_FreeBSD_Host
     (Partition : in out FBVBS.ABI.Partition_Descriptor;
      Status    : out FBVBS.ABI.Status_Code)
     with
       Post =>
         ((if Status = FBVBS.ABI.OK then
               Partition.In_Use
               and then Partition.Partition_Id = 1
               and then Partition.Kind = FBVBS.ABI.Partition_FreeBSD_Host
               and then Partition.State = FBVBS.ABI.Runnable
             else
                Partition = Partition'Old));

   procedure Validate_Create_Profile
     (Requested_VCPU_Count   : FBVBS.ABI.U32;
      Expected_VCPU_Count    : FBVBS.ABI.U32;
      Requested_Memory_Limit : FBVBS.ABI.U64;
      Expected_Memory_Limit  : FBVBS.ABI.U64;
      Requested_Capability   : FBVBS.ABI.U64;
      Expected_Capability    : FBVBS.ABI.U64;
      Status                 : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             Requested_VCPU_Count = Expected_VCPU_Count
             and then Requested_Memory_Limit = Expected_Memory_Limit
             and then Requested_Capability = Expected_Capability);

   procedure Validate_Load_Profile
     (Requested_Entry_IP    : FBVBS.ABI.U64;
      Expected_Entry_IP     : FBVBS.ABI.U64;
      Requested_Initial_SP  : FBVBS.ABI.U64;
      Expected_Initial_SP   : FBVBS.ABI.U64;
      Require_Explicit_Stack : Boolean;
      Status                : out FBVBS.ABI.Status_Code)
      with
        Post =>
          (if Status = FBVBS.ABI.OK then
              (Requested_Entry_IP = 0 or else Requested_Entry_IP = Expected_Entry_IP)
              and then
              (if Require_Explicit_Stack then
                   Requested_Initial_SP /= 0
               else
                   Requested_Initial_SP = 0 or else Requested_Initial_SP = Expected_Initial_SP));

    procedure Measure
      (Partition        : in out FBVBS.ABI.Partition_Descriptor;
       Approval_Present : Boolean;
       Status           : out FBVBS.ABI.Status_Code)
      with
        Post =>
          ((if Status = FBVBS.ABI.OK then
                 Approval_Present and then Partition.State = FBVBS.ABI.Measured
             else Partition = Partition'Old));

   procedure Get_Status
     (Partition : FBVBS.ABI.Partition_Descriptor;
      Result    : out FBVBS.ABI.Partition_Status_Record;
      Status    : out FBVBS.ABI.Status_Code)
     with
       Post =>
          (if Status = FBVBS.ABI.OK then
              Result.State = Partition.State
              and then Result.Measurement_Epoch = Partition.Measurement_Epoch);

   procedure Get_Fault_Info
     (Partition : FBVBS.ABI.Partition_Descriptor;
      Result    : out FBVBS.ABI.Fault_Info_Record;
      Status    : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             Result.Fault_Code = Partition.Last_Fault_Code
             and then Result.Source_Component = Partition.Last_Source_Component);

    procedure Load
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Status    : out FBVBS.ABI.Status_Code)
     with
       Post =>
         ((if Status = FBVBS.ABI.OK then Partition.State = FBVBS.ABI.Loaded
           else Partition = Partition'Old));

    procedure Start
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Status    : out FBVBS.ABI.Status_Code)
      with
        Post =>
          ((if Status = FBVBS.ABI.OK then Partition.State = FBVBS.ABI.Runnable
            else Partition = Partition'Old));

    procedure Quiesce
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Status    : out FBVBS.ABI.Status_Code)
      with
        Post =>
          ((if Status = FBVBS.ABI.OK then Partition.State = FBVBS.ABI.Quiesced
            else Partition = Partition'Old));

     procedure Resume
       (Partition : in out FBVBS.ABI.Partition_Descriptor;
        Status    : out FBVBS.ABI.Status_Code)
       with
         Post =>
           ((if Status = FBVBS.ABI.OK then Partition.State = FBVBS.ABI.Runnable
             else Partition = Partition'Old));

     procedure Refresh_VM_State
       (Partition                : in out FBVBS.ABI.Partition_Descriptor;
        Any_Running              : Boolean;
        Any_Runnable_Or_Blocked  : Boolean;
        Any_Faulted              : Boolean;
        Status                   : out FBVBS.ABI.Status_Code)
       with
         Post =>
           ((if Status = FBVBS.ABI.OK and then Any_Faulted then
                 Partition.State = FBVBS.ABI.Faulted
             elsif Status = FBVBS.ABI.OK and then Any_Running then
                 Partition.State = FBVBS.ABI.Running
             elsif Status = FBVBS.ABI.OK and then Any_Runnable_Or_Blocked then
                 Partition.State = FBVBS.ABI.Runnable
             elsif Status /= FBVBS.ABI.OK then
                 Partition = Partition'Old));

      procedure Fault
        (Partition : in out FBVBS.ABI.Partition_Descriptor;
         Status    : out FBVBS.ABI.Status_Code)
       with
         Post =>
           ((if Status = FBVBS.ABI.OK then Partition.State = FBVBS.ABI.Faulted
             else Partition = Partition'Old));

   procedure Fault
     (Partition        : in out FBVBS.ABI.Partition_Descriptor;
      Fault_Code       : FBVBS.ABI.U32;
      Source_Component : FBVBS.ABI.U32;
      Detail0          : FBVBS.ABI.U64;
      Detail1          : FBVBS.ABI.U64;
      Status           : out FBVBS.ABI.Status_Code)
     with
       Post =>
         ((if Status = FBVBS.ABI.OK then
               Partition.State = FBVBS.ABI.Faulted
               and then Partition.Last_Fault_Code = Fault_Code
           else
               Partition = Partition'Old));

    procedure Recover
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Has_Image : Boolean;
       Status    : out FBVBS.ABI.Status_Code)
      with
        Post =>
          ((if Status = FBVBS.ABI.OK then
               Partition.State = FBVBS.ABI.Runnable and then
               Partition.Measurement_Epoch = Partition.Measurement_Epoch'Old + 1
            else
               Partition = Partition'Old));

   procedure Destroy
     (Partition : in out FBVBS.ABI.Partition_Descriptor;
      Status    : out FBVBS.ABI.Status_Code)
     with
       Post =>
         ((if Status = FBVBS.ABI.OK then Partition.State = FBVBS.ABI.Destroyed
           else Partition = Partition'Old));

     procedure Bind_Service
       (Partition    : in out FBVBS.ABI.Partition_Descriptor;
        Service_Kind : FBVBS.ABI.Trusted_Service_Kind;
        Status       : out FBVBS.ABI.Status_Code)
       with
         Post =>
           ((if Status = FBVBS.ABI.OK then
                 Partition.Kind = FBVBS.ABI.Partition_Trusted_Service and then
                 Partition.State = FBVBS.ABI.Measured and then
                 Partition.Service_Kind = Service_Kind
             else Partition = Partition'Old));
end FBVBS.Partitions;
