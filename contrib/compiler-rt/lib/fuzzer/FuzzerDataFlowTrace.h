//===- FuzzerDataFlowTrace.h - Internal header for the Fuzzer ---*- C++ -* ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// fuzzer::DataFlowTrace; reads and handles a data-flow trace.
//
// A data flow trace is generated by e.g. dataflow/DataFlow.cpp
// and is stored on disk in a separate directory.
//
// The trace dir contains a file 'functions.txt' which lists function names,
// oner per line, e.g.
// ==> functions.txt <==
// Func2
// LLVMFuzzerTestOneInput
// Func1
//
// All other files in the dir are the traces, see dataflow/DataFlow.cpp.
// The name of the file is sha1 of the input used to generate the trace.
//
// Current status:
//   the data is parsed and the summary is printed, but the data is not yet
//   used in any other way.
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_DATA_FLOW_TRACE
#define LLVM_FUZZER_DATA_FLOW_TRACE

#include "FuzzerDefs.h"

#include <unordered_map>
#include <vector>
#include <string>

namespace fuzzer {
class DataFlowTrace {
 public:
  void Init(const std::string &DirPath, const std::string &FocusFunction);
  void Clear() { Traces.clear(); }
  const Vector<uint8_t> *Get(const std::string &InputSha1) const {
    auto It = Traces.find(InputSha1);
    if (It != Traces.end())
      return &It->second;
    return nullptr;
  }

 private:
  // Input's sha1 => DFT for the FocusFunction.
  std::unordered_map<std::string, Vector<uint8_t> > Traces;
};
}  // namespace fuzzer

#endif // LLVM_FUZZER_DATA_FLOW_TRACE
