from django.core.exceptions import PermissionDenied


class BoardActions:
    def move_cards(self, request, source_board, target_board):
        cards = source_board.cards()
        if not source_board.check_access(request.user):
            raise PermissionDenied("no access")
        if not target_board.check_access(request.user):
            raise PermissionDenied("no access")
        for card in cards:
            card.board = target_board
            card.save()

    def copy_cards(self, request, source_board, target_board):
        cards = source_board.cards()
        if not target_board.check_access(request.user):
            raise PermissionDenied("no access")
        for card in cards:
            target_board.add(card.clone())
