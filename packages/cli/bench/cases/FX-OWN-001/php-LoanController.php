<?php

namespace App\Http\Controllers;

class LoanController extends Controller
{
    public function show($id)
    {
        $loan = Loan::find($id); // @hit
        return response()->json($loan);
    }

    public function statement($loanId)
    {
        $loan = Loan::findOrFail($loanId); // @hit
        return $loan->statement();
    }

    public function destroy(Request $request)
    {
        $loan = Loan::findOrFail($request->id); // @hit
        $loan->delete();
    }

    public function update($id)
    {
        $loan = Loan::where('id', $id)->first(); // @hit
        return $loan;
    }
}
