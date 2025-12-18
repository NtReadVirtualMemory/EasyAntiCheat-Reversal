void __fastcall EAC::HandleIOPacket(IRP *Irp, TEST_IO_STACK_LOCATION *IrpStack, _DWORD *OutBytes)
{
  __int64 ClientData; // rdi
  EAC_COMMAND_PACKET *v5; // rbx
  __m128 *Type3InputBuffer; // r14
  unsigned __int64 PacketSize; // rsi
  EAC_COMMAND_PACKET *v8; // rax
  unsigned __int64 v9; // rax
  __int64 CurrentProcess; // rax
  char success; // al

  ClientData = 0LL;
  v5 = 0LL;
  Type3InputBuffer = (__m128 *)IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
  if ( Type3InputBuffer )
  {
    PacketSize = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    if ( (unsigned int)PacketSize > 8
      && Irp->UserBuffer == Type3InputBuffer
      && IrpStack->Parameters.DeviceIoControl.OutputBufferLength == (_DWORD)PacketSize )
    {
      EAC::AnalyseLatetr((unsigned __int64)Type3InputBuffer, (unsigned int)PacketSize, 1);
      v8 = (EAC_COMMAND_PACKET *)EAC::Memory::malloc((unsigned int)PacketSize);
      v5 = v8;
      if ( v8 )
      {
        EAC::Memory::memcpy((__m128 *)v8, Type3InputBuffer, (unsigned int)PacketSize);
        ClientData = (__int64)EAC::GetClientData(v5->Header.HandleID);
        if ( ClientData )
        {
          v9 = EAC::Crypto::DecryptPointer(qword_2091A8);
          CurrentProcess = ((__int64 (__fastcall *)(unsigned __int64))(__ROR8__(~v9, 0x1F) ^ 0xD00C52EC151785ABuLL))();// PsGetCurrentProcess
          if ( (unsigned __int8)sub_E8760(CurrentProcess) )
          {
            switch ( v5->Header.CommandID )
            {
              case 1u:
                if ( (_DWORD)PacketSize != 0x28 )
                  goto Cleanup;
                success = EAC::ZwAllocVM(*(_QWORD *)(ClientData + 0x38), (EAC_ALLOC_PACKET *)v5);
                break;
              case 2u:
                if ( (_DWORD)PacketSize != 0x28 )
                  goto Cleanup;
                success = EAC::ZwReadVM(*(_QWORD *)(ClientData + 0x38), (EAC_READ_PACKET *)v5);
                break;
              case 3u:
                if ( (_DWORD)PacketSize != 0x28 )
                  goto Cleanup;
                success = EAC::ZwWriteVM(*(_QWORD *)(ClientData + 0x38), (__int64)v5);
                break;
              case 4u:
                if ( (_DWORD)PacketSize != 0x20 )
                  goto Cleanup;
                success = EAC::ZwProtectVM(*(_QWORD *)(ClientData + 0x38), (EAC_PROTECT_PACKET *)v5);
                break;
              case 5u:
                if ( (_DWORD)PacketSize != 0x1C )
                  goto Cleanup;
                success = EAC::ZwFreeVM(*(_QWORD *)(ClientData + 0x38), (EAC_FREE_PACKET *)v5);
                break;
              case 6u:
                if ( (_DWORD)PacketSize != 0x24 )
                  goto Cleanup;
                success = EAC::ZwFlushVirtualMemory(*(_QWORD *)(ClientData + 0x38), (__int64)v5);
                break;
              case 7u:
                if ( (_DWORD)PacketSize != 0x24 )
                  goto Cleanup;
                success = EAC::ZwQueryVirtualMemory(*(_QWORD *)(ClientData + 0x38), (__int64)v5);
                break;
              default:
                if ( v5->Header.CommandID != 8 || (_DWORD)PacketSize != 0x24 )
                  goto Cleanup;
                success = EAC::ZwSetInformationVirtualMemory(*(_QWORD *)(ClientData + 0x38), (__int64)v5);
                break;
            }
            if ( success )
            {
              EAC::Memory::memcpy(Type3InputBuffer, (__m128 *)v5, PacketSize);
              *OutBytes = PacketSize;
            }
          }
        }
      }
    }
  }
Cleanup:
  if ( v5 )
    EAC::Memory::Free((__int64)v5);
  if ( ClientData )
    EAC::DereferenceObject(ClientData);
}
