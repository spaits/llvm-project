#ifndef LLVM_LIB_CODEGEN_MACHINECOPYPROPAGATION_H
#define LLVM_LIB_CODEGEN_MACHINECOPYPROPAGATION_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"

#include <cassert>
#include <optional>

namespace llvm {


std::optional<DestSourcePair> isCopyInstr(const MachineInstr &MI,
                                          const TargetInstrInfo &TII,
                                           bool UseCopyInstr);

class CopyTracker {
  struct CopyInfo {
    MachineInstr *MI, *LastSeenUseInCopy;
    SmallVector<MCRegister, 4> DefRegs;
    bool Avail;
  };
  

  // Store information about invalidated copies. This information can be later
  // used to optimize data dependencies.
  struct InvalidCopyInfo {
    MachineInstr *MI, *LastSeenUseInCopy;
    SmallVector<MCRegister, 4> DefRegs;
    bool Avail;
    MachineInstr *InvalidatedBy;
    MachineInstr *Destination = nullptr;
    MCRegUnit KeyRegisterUnit;
    InvalidCopyInfo(MCRegUnit KeyRegisterUnit, const CopyInfo &CI, MachineInstr *InvalidatedBy) {
      this->KeyRegisterUnit = KeyRegisterUnit;
      this->MI = CI.MI;
      this->LastSeenUseInCopy = CI.LastSeenUseInCopy;
      // Is this shallow or deep copy?
      this->DefRegs = CI.DefRegs;
      this->Avail = CI.Avail;
      this->InvalidatedBy = InvalidatedBy;
    }
  };

  struct SuccessfulCopyPropagationInfo {
    MachineInstr *Source, *Dest;
    MCRegUnit KeyRegister;
    SuccessfulCopyPropagationInfo(MCRegUnit KeyRegister, MachineInstr *Source, MachineInstr *Dest) : Source(Source), Dest(Dest), KeyRegister(KeyRegister) {}
  };

  DenseMap<MCRegUnit, CopyInfo> Copies;
  llvm::SmallVector<InvalidCopyInfo> InvalidCopies;
  llvm::SmallVector<SuccessfulCopyPropagationInfo> SuccessfullyPropagatedCopies;

public:

  llvm::SmallVector<InvalidCopyInfo> getInvalidCopies() const {
    return InvalidCopies;
  }

  llvm::SmallVector<SuccessfulCopyPropagationInfo> getSuccessfullyPropagatedCopies() const {
    return SuccessfullyPropagatedCopies;
  }

  void addSuccessfullyPropagatedCopy(MCRegUnit KeyRegister, MachineInstr *Source, MachineInstr *Dest) {
    SuccessfullyPropagatedCopies.push_back(SuccessfulCopyPropagationInfo{KeyRegister, Source, Dest});
  }

  bool hasSuccessfulPropagationHappenedWithIt(Register Reg, MachineInstr *MI) {
    for (auto SuccessfulCopyProp : SuccessfullyPropagatedCopies) {
      if (SuccessfulCopyProp.KeyRegister == Reg && SuccessfulCopyProp.Dest == MI)
        return true;
    }
    return false;
  }
  
  /// Mark all of the given registers and their subregisters as unavailable for
  /// copying.
  void markRegsUnavailable(ArrayRef<MCRegister> Regs,
                           const TargetRegisterInfo &TRI) {
    for (MCRegister Reg : Regs) {
      // Source of copy is no longer available for propagation.
      for (MCRegUnit Unit : TRI.regunits(Reg)) {
        auto CI = Copies.find(Unit);
        if (CI != Copies.end())
          CI->second.Avail = false;
      }
    }
  }

  /// Remove register from copy maps.
  void invalidateRegister(MCRegister Reg, const TargetRegisterInfo &TRI,
                          const TargetInstrInfo &TII, bool UseCopyInstr,
                          MachineInstr *InvalidatedBy = nullptr) {
    // Since Reg might be a subreg of some registers, only invalidate Reg is not
    // enough. We have to find the COPY defines Reg or registers defined by Reg
    // and invalidate all of them. Similarly, we must invalidate all of the
    // the subregisters used in the source of the COPY.
    SmallSet<MCRegUnit, 8> RegUnitsToInvalidate;
    auto InvalidateCopy = [&](MachineInstr *MI) {
      std::optional<DestSourcePair> CopyOperands =
          isCopyInstr(*MI, TII, UseCopyInstr);
      assert(CopyOperands && "Expect copy");

      auto Dest = TRI.regunits(CopyOperands->Destination->getReg().asMCReg());
      auto Src = TRI.regunits(CopyOperands->Source->getReg().asMCReg());
      RegUnitsToInvalidate.insert(Dest.begin(), Dest.end());
      RegUnitsToInvalidate.insert(Src.begin(), Src.end());
    };

    for (MCRegUnit Unit : TRI.regunits(Reg)) {
      auto I = Copies.find(Unit);
      if (I != Copies.end()) {
        if (MachineInstr *MI = I->second.MI)
          InvalidateCopy(MI);
        if (MachineInstr *MI = I->second.LastSeenUseInCopy)
          InvalidateCopy(MI);
      }
    }

    bool HasSuccessfulPropagationHappenedWithIt = this->hasSuccessfulPropagationHappenedWithIt(Reg, InvalidatedBy);

    for (MCRegUnit Unit : RegUnitsToInvalidate) {
      if (Copies.contains(Unit) && !HasSuccessfulPropagationHappenedWithIt) {
        InvalidCopies.push_back(InvalidCopyInfo{Unit, Copies[Unit],InvalidatedBy});
      }
      Copies.erase(Unit);
    }
  }

  /// Clobber a single register, removing it from the tracker's copy maps.
  void clobberRegister(MCRegister Reg, const TargetRegisterInfo &TRI,
                       const TargetInstrInfo &TII, bool UseCopyInstr) {
    for (MCRegUnit Unit : TRI.regunits(Reg)) {
      auto I = Copies.find(Unit);
      if (I != Copies.end()) {
        // When we clobber the source of a copy, we need to clobber everything
        // it defined.
        markRegsUnavailable(I->second.DefRegs, TRI);
        // When we clobber the destination of a copy, we need to clobber the
        // whole register it defined.
        if (MachineInstr *MI = I->second.MI) {
          std::optional<DestSourcePair> CopyOperands =
              isCopyInstr(*MI, TII, UseCopyInstr);

          MCRegister Def = CopyOperands->Destination->getReg().asMCReg();
          MCRegister Src = CopyOperands->Source->getReg().asMCReg();

          markRegsUnavailable(Def, TRI);

          // Since we clobber the destination of a copy, the semantic of Src's
          // "DefRegs" to contain Def is no longer effectual. We will also need
          // to remove the record from the copy maps that indicates Src defined
          // Def. Failing to do so might cause the target to miss some
          // opportunities to further eliminate redundant copy instructions.
          // Consider the following sequence during the
          // ForwardCopyPropagateBlock procedure:
          // L1: r0 = COPY r9     <- TrackMI
          // L2: r0 = COPY r8     <- TrackMI (Remove r9 defined r0 from tracker)
          // L3: use r0           <- Remove L2 from MaybeDeadCopies
          // L4: early-clobber r9 <- Clobber r9 (L2 is still valid in tracker)
          // L5: r0 = COPY r8     <- Remove NopCopy
          for (MCRegUnit SrcUnit : TRI.regunits(Src)) {
            auto SrcCopy = Copies.find(SrcUnit);
            if (SrcCopy != Copies.end() && SrcCopy->second.LastSeenUseInCopy) {
              // If SrcCopy defines multiple values, we only need
              // to erase the record for Def in DefRegs.
              for (auto itr = SrcCopy->second.DefRegs.begin();
                   itr != SrcCopy->second.DefRegs.end(); itr++) {
                if (*itr == Def) {
                  SrcCopy->second.DefRegs.erase(itr);
                  // If DefReg becomes empty after removal, we can remove the
                  // SrcCopy from the tracker's copy maps. We only remove those
                  // entries solely record the Def is defined by Src. If an
                  // entry also contains the definition record of other Def'
                  // registers, it cannot be cleared.
                  if (SrcCopy->second.DefRegs.empty() && !SrcCopy->second.MI) {
                    Copies.erase(SrcCopy);
                  }
                  break;
                }
              }
            }
          }
        }
        // Now we can erase the copy.
        Copies.erase(I);
      }
    }
  }

  /// Add this copy's registers into the tracker's copy maps.
  void trackCopy(MachineInstr *MI, const TargetRegisterInfo &TRI,
                 const TargetInstrInfo &TII, bool UseCopyInstr) {
    std::optional<DestSourcePair> CopyOperands =
        isCopyInstr(*MI, TII, UseCopyInstr);
    assert(CopyOperands && "Tracking non-copy?");

    MCRegister Src = CopyOperands->Source->getReg().asMCReg();
    MCRegister Def = CopyOperands->Destination->getReg().asMCReg();

    // Remember Def is defined by the copy.
    for (MCRegUnit Unit : TRI.regunits(Def))
      Copies[Unit] = {MI, nullptr, {}, true};

    // Remember source that's copied to Def. Once it's clobbered, then
    // it's no longer available for copy propagation.
    for (MCRegUnit Unit : TRI.regunits(Src)) {
      auto I = Copies.insert({Unit, {nullptr, nullptr, {}, false}});
      auto &Copy = I.first->second;
      if (!is_contained(Copy.DefRegs, Def))
        Copy.DefRegs.push_back(Def);
      Copy.LastSeenUseInCopy = MI;
    }
  }

  bool hasAnyCopies() {
    return !Copies.empty();
  }

  MachineInstr *findCopyForUnit(MCRegUnit RegUnit,
                                const TargetRegisterInfo &TRI,
                                bool MustBeAvailable = false) {
    auto CI = Copies.find(RegUnit);
    if (CI == Copies.end())
      return nullptr;
    if (MustBeAvailable && !CI->second.Avail)
      return nullptr;
    return CI->second.MI;
  }

  MachineInstr *findCopyDefViaUnit(MCRegUnit RegUnit,
                                   const TargetRegisterInfo &TRI) {
    auto CI = Copies.find(RegUnit);
    if (CI == Copies.end())
      return nullptr;
    if (CI->second.DefRegs.size() != 1)
      return nullptr;
    MCRegUnit RU = *TRI.regunits(CI->second.DefRegs[0]).begin();
    return findCopyForUnit(RU, TRI, true);
  }

  MachineInstr *findAvailBackwardCopy(MachineInstr &I, MCRegister Reg,
                                      const TargetRegisterInfo &TRI,
                                      const TargetInstrInfo &TII,
                                      bool UseCopyInstr) {
    MCRegUnit RU = *TRI.regunits(Reg).begin();
    MachineInstr *AvailCopy = findCopyDefViaUnit(RU, TRI);

    if (!AvailCopy)
      return nullptr;

    std::optional<DestSourcePair> CopyOperands =
        isCopyInstr(*AvailCopy, TII, UseCopyInstr);
    Register AvailSrc = CopyOperands->Source->getReg();
    Register AvailDef = CopyOperands->Destination->getReg();
    if (!TRI.isSubRegisterEq(AvailSrc, Reg))
      return nullptr;

    for (const MachineInstr &MI :
         make_range(AvailCopy->getReverseIterator(), I.getReverseIterator()))
      for (const MachineOperand &MO : MI.operands())
        if (MO.isRegMask())
          // FIXME: Shall we simultaneously invalidate AvailSrc or AvailDef?
          if (MO.clobbersPhysReg(AvailSrc) || MO.clobbersPhysReg(AvailDef))
            return nullptr;

    return AvailCopy;
  }

  MachineInstr *findAvailCopy(MachineInstr &DestCopy, MCRegister Reg,
                              const TargetRegisterInfo &TRI,
                              const TargetInstrInfo &TII, bool UseCopyInstr) {
    // We check the first RegUnit here, since we'll only be interested in the
    // copy if it copies the entire register anyway.
    MCRegUnit RU = *TRI.regunits(Reg).begin();
    MachineInstr *AvailCopy =
        findCopyForUnit(RU, TRI, /*MustBeAvailable=*/true);

    if (!AvailCopy)
      return nullptr;

    std::optional<DestSourcePair> CopyOperands =
        isCopyInstr(*AvailCopy, TII, UseCopyInstr);
    Register AvailSrc = CopyOperands->Source->getReg();
    Register AvailDef = CopyOperands->Destination->getReg();
    if (!TRI.isSubRegisterEq(AvailDef, Reg))
      return nullptr;

    // Check that the available copy isn't clobbered by any regmasks between
    // itself and the destination.
    for (const MachineInstr &MI :
         make_range(AvailCopy->getIterator(), DestCopy.getIterator()))
      for (const MachineOperand &MO : MI.operands())
        if (MO.isRegMask())
          if (MO.clobbersPhysReg(AvailSrc) || MO.clobbersPhysReg(AvailDef))
            return nullptr;

    return AvailCopy;
  }

  // Find last COPY that defines Reg before Current MachineInstr.
  MachineInstr *findLastSeenDefInCopy(const MachineInstr &Current,
                                      MCRegister Reg,
                                      const TargetRegisterInfo &TRI,
                                      const TargetInstrInfo &TII,
                                      bool UseCopyInstr) {
    MCRegUnit RU = *TRI.regunits(Reg).begin();
    auto CI = Copies.find(RU);
    if (CI == Copies.end() || !CI->second.Avail)
      return nullptr;

    MachineInstr *DefCopy = CI->second.MI;
    std::optional<DestSourcePair> CopyOperands =
        isCopyInstr(*DefCopy, TII, UseCopyInstr);
    Register Def = CopyOperands->Destination->getReg();
    if (!TRI.isSubRegisterEq(Def, Reg))
      return nullptr;

    for (const MachineInstr &MI :
         make_range(static_cast<const MachineInstr *>(DefCopy)->getIterator(),
                    Current.getIterator()))
      for (const MachineOperand &MO : MI.operands())
        if (MO.isRegMask())
          if (MO.clobbersPhysReg(Def)) {
            //llvm::LLVM_DEBUG(dbgs() << "MCP: Removed tracking of "
            //                  << printReg(Def, &TRI) << "\n");
            return nullptr;
          }

    return DefCopy;
  }

  // Find last COPY that uses Reg.
  MachineInstr *findLastSeenUseInCopy(MCRegister Reg,
                                      const TargetRegisterInfo &TRI) {
    MCRegUnit RU = *TRI.regunits(Reg).begin();
    auto CI = Copies.find(RU);
    if (CI == Copies.end())
      return nullptr;
    return CI->second.LastSeenUseInCopy;
  }

  void clear() {
    Copies.clear();
  }
};

class BackwardPropagationCL {
private:
  const TargetRegisterInfo *TRI = nullptr;
  const TargetInstrInfo *TII = nullptr;
  const MachineRegisterInfo *MRI = nullptr;
  bool UseCopyInstr;

  CopyTracker Tracker;
  SmallSetVector<MachineInstr *, 8> MaybeDeadCopies;
  DenseMap<MachineInstr *, SmallSet<MachineInstr *, 2>> CopyDbgUsers;
  bool &Changed;

public:
  BackwardPropagationCL(const TargetRegisterInfo *TRI,
                        const TargetInstrInfo *TII,
                        const MachineRegisterInfo *MRI, bool UseCopyInstr,
                        bool &Changed)
      : Changed(Changed) {
    this->TRI = TRI;
    this->TII = TII;
    this->MRI = MRI;
    this->UseCopyInstr = UseCopyInstr;
  }

  CopyTracker backwardCopyPropagateBlock(MachineBasicBlock &MBB,
                                         bool Analysis = false);
  void propagateDefs(MachineInstr &MI, bool Analysis = false);
  bool isBackwardPropagatableRegClassCopy(const MachineInstr &Copy,
                                          const MachineInstr &UseI,
                                          unsigned UseIdx);
  bool hasImplicitOverlap(const MachineInstr &MI, const MachineOperand &Use);
  bool hasOverlappingMultipleDef(const MachineInstr &MI,
                                 const MachineOperand &MODef, Register Def);
  CopyTracker backwardCopyPropagateBlockRanges(MachineBasicBlock::iterator RegionBegin, MachineBasicBlock::iterator RegionEnd, bool Analysis);
};

} // end of namespace llvm
#endif // LLVM_LIB_CODEGEN_MACHINECOPYPROPAGATION_H