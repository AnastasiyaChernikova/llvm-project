//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ProTypeConstCastCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/SourceManager.h"

using namespace clang::ast_matchers;

namespace clang::tidy::cppcoreguidelines {

static bool hasConstQualifier(QualType Type) {
  const QualType PtrType = Type->getPointeeType();
  if (!PtrType.isNull())
    return hasConstQualifier(PtrType);

  return Type.isConstQualified();
}

static bool hasVolatileQualifier(QualType Type) {
  const QualType PtrType = Type->getPointeeType();
  if (!PtrType.isNull())
    return hasVolatileQualifier(PtrType);
  return Type.isVolatileQualified();
}

ProTypeConstCastCheck::ProTypeConstCastCheck(StringRef Name,
                                             ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      StrictMode(Options.get("StrictMode", false)) {}

void ProTypeConstCastCheck::storeOptions(ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "StrictMode", StrictMode);
}

void ProTypeConstCastCheck::registerMatchers(MatchFinder *Finder) {
  // We leave the existing const_cast (C++) check — bind "cast".
  Finder->addMatcher(cxxConstCastExpr().bind("cast"), this);
  // Tracking C-style casts and varDecl initialized by a C-style cast.
  Finder->addMatcher(cStyleCastExpr().bind("cStyleCast"), this);
  Finder->addMatcher(
      varDecl(hasInitializer(cStyleCastExpr())).bind("varInitWithCStyleCast"),
      this);
}

void ProTypeConstCastCheck::check(const MatchFinder::MatchResult &Result) {
  // Existing logic for C++ const_cast.
  if (const auto *MatchedCast =
          Result.Nodes.getNodeAs<CXXConstCastExpr>("cast")) {
    if (StrictMode) {
      diag(MatchedCast->getOperatorLoc(), "do not use const_cast");
      return;
    }

    const QualType TargetType = MatchedCast->getType().getCanonicalType();
    const QualType SourceType =
        MatchedCast->getSubExpr()->getType().getCanonicalType();

    const bool RemovingConst =
        hasConstQualifier(SourceType) && !hasConstQualifier(TargetType);
    const bool RemovingVolatile =
        hasVolatileQualifier(SourceType) && !hasVolatileQualifier(TargetType);

    if (!RemovingConst && !RemovingVolatile)
      return;

    diag(MatchedCast->getOperatorLoc(),
         "do not use const_cast to remove%select{| const}0%select{| "
         "and}2%select{| volatile}1 qualifier")
        << RemovingConst << RemovingVolatile
        << (RemovingConst && RemovingVolatile);
    return;
  }

  // Handling varDecl with a c-style cast initializer:
  // varDecl(hasInitializer(cStyleCastExpr())).
  if (const auto *VarInit =
          Result.Nodes.getNodeAs<VarDecl>("varInitWithCStyleCast")) {
    const Expr *Init = VarInit->getInit();
    if (Init) {
      const Expr *InitSub = Init->IgnoreParenImpCasts();
      if (const auto *InitCast = dyn_cast_or_null<CStyleCastExpr>(InitSub)) {
        const Expr *CastSub = InitCast->getSubExpr();
        if (CastSub) {
          const Expr *CastSubClean = CastSub->IgnoreParenImpCasts();
          if (CastSubClean) {
            QualType FromT = CastSubClean->getType();
            QualType ToT = InitCast->getType();
            if (!FromT.isNull() && !ToT.isNull() && FromT->isPointerType() &&
                ToT->isVoidPointerType()) {
              QualType Pointee = FromT->getPointeeType();
              if (Pointee.isConstQualified()) {
                SourceLocation VL = VarInit->getLocation();
                if (VL.isValid())
                  RecordedVoidVarLocs.push_back(VL);
              }
            }
          }
        }
      }
    }
  }

  // Handling C-style cast expressions.
  if (const auto *CStyle =
          Result.Nodes.getNodeAs<CStyleCastExpr>("cStyleCast")) {
    if (!CStyle)
      return;
    const ASTContext &Ctx = *Result.Context;
    const SourceManager &SM = Ctx.getSourceManager();

    const Expr *Sub = CStyle->getSubExpr();
    if (!Sub)
      return;
    Sub = Sub->IgnoreParenImpCasts();
    if (!Sub)
      return;

    QualType FromType = Sub->getType();
    QualType ToType = CStyle->getType();
    if (FromType.isNull() || ToType.isNull())
      return;

    // const T* -> void* — save the position of the sub-expression.
    if (FromType->isPointerType() && ToType->isVoidPointerType()) {
      QualType Pointee = FromType->getPointeeType();
      if (Pointee.isConstQualified()) {
        SourceLocation L = Sub->getExprLoc();
        if (L.isValid())
          RecordedVoidCastLocs.push_back(L);
        return;
      }
    }

    // void* -> T* (without const) — we check whether const was previously
    // removed via void*.
    if (FromType->isPointerType() && FromType->getPointeeType()->isVoidType() &&
        ToType->isPointerType()) {
      QualType ToPointee = ToType->getPointeeType();
      if (!ToPointee.isConstQualified()) {
        SourceLocation SubLoc = Sub->getExprLoc();
        if (!SubLoc.isValid())
          return;

        // Compare with source locations saved with const->void.
        for (const SourceLocation &RecLoc : RecordedVoidCastLocs) {
          if (!RecLoc.isValid())
            continue;
          bool RecBeforeSub = SM.isBeforeInTranslationUnit(RecLoc, SubLoc);
          bool SubBeforeRec = SM.isBeforeInTranslationUnit(SubLoc, RecLoc);
          if (!RecBeforeSub && !SubBeforeRec) {
            diag(CStyle->getBeginLoc(), "removing const via intermediate void* "
                                        "produces undefined behavior")
                << CStyle->getSourceRange();
            return;
          }
        }

        // If the sub-expression is a DeclRefExpr (e.g. 'vp'), compare
        // with previously saved VarDecl locations.
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
          if (const Decl *D = DRE->getDecl()) {
            SourceLocation DLoc = D->getLocation();
            if (DLoc.isValid()) {
              for (const SourceLocation &VLoc : RecordedVoidVarLocs) {
                if (!VLoc.isValid())
                  continue;
                bool VBeforeD = SM.isBeforeInTranslationUnit(VLoc, DLoc);
                bool DBeforeV = SM.isBeforeInTranslationUnit(DLoc, VLoc);
                if (!VBeforeD && !DBeforeV) {
                  diag(CStyle->getBeginLoc(),
                       "removing const via intermediate void* produces "
                       "undefined behavior")
                      << CStyle->getSourceRange();
                  return;
                }
              }
            }
          }
        }
      }
    }
    return;
  }
}

} // namespace clang::tidy::cppcoreguidelines
