<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;

class InvoiceController extends Controller
{
    public function edit(Invoice $invoice)
    {
        $this->authorize('update', $invoice);
        return view('invoices.edit', compact('invoice'));
    }

    public function update(Request $request, Invoice $invoice)
    {
        $this->authorize('update', $invoice);
        $invoice->update($request->validated());
        return redirect()->route('invoices.show', $invoice);
    }

    public function destroy(Invoice $invoice)
    {
        $this->authorize('delete', $invoice);
        $invoice->delete();
        return redirect()->route('invoices.index');
    }

    public function show(Invoice $invoice)
    {
        $this->authorize('view', $invoice);
        return view('invoices.show', compact('invoice'));
    }
}
