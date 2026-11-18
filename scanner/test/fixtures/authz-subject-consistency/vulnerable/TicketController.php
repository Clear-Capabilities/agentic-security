<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Http\Request;

class TicketController extends Controller
{
    public function show($id)
    {
        $this->authorize('view', Ticket::class);
        $ticket = Ticket::findOrFail($id);
        $this->authorize('view', $ticket);
        return $ticket;
    }

    public function comments(Ticket $ticket)
    {
        $this->authorize('view', $ticket);
        return $ticket->comments;
    }

    public function history(Request $request, $id)
    {
        if ($ticket = Ticket::where('id', $id)->first()) {
            $this->authorize('view', $ticket);
            return $ticket->history;
        }
        abort(404);
    }

    public function attachments(Ticket $ticket)
    {
        $this->authorize('view', Ticket::class);
        return $ticket->attachments;
    }

    public function index()
    {
        $this->authorize('view', Ticket::class);
        return Ticket::paginate();
    }
}
