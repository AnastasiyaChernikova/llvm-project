//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_CPPCOREGUIDELINES_PROTYPECONSTCASTCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_CPPCOREGUIDELINES_PROTYPECONSTCASTCHECK_H

#include "../ClangTidyCheck.h"

namespace clang::tidy::cppcoreguidelines {

/// Imposes limitations on the use of const_cast within C++ code.
///
/// For the user-facing documentation see:
/// https://clang.llvm.org/extra/clang-tidy/checks/cppcoreguidelines/pro-type-const-cast.html
class ProTypeConstCastCheck : public ClangTidyCheck {
public:
  ProTypeConstCastCheck(StringRef Name, ClangTidyContext *Context);
  bool isLanguageVersionSupported(const LangOptions &LangOpts) const override {
    return LangOpts.CPlusPlus;
  }
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
  void storeOptions(ClangTidyOptions::OptionMap &Opts) override;
  std::optional<TraversalKind> getCheckTraversalKind() const override {
    return TK_IgnoreUnlessSpelledInSource;
  }

private:
  const bool StrictMode;
  // For simple detection of const T* -> (void*) -> T* conversions, we store
  // the locations of sub-expressions and the locations of VarDecls initialized
  // by such casts. SourceLocation can be safely stored between check() calls.
  llvm::SmallVector<clang::SourceLocation, 8> RecordedVoidCastLocs;
  llvm::SmallVector<clang::SourceLocation, 8> RecordedVoidVarLocs;
};

} // namespace clang::tidy::cppcoreguidelines

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_CPPCOREGUIDELINES_PROTYPECONSTCASTCHECK_H
