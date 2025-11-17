# Simple implementation of blackjack logic
# This blackjack game will feature 4 decks, totalling 208 cards (52 * 4)
# Dealer will hit on soft 17 (Ace + 6), hit on 16 and stand on 17+
import os
from cryptography.hazmat.primitives import hashes, hmac

# We define the deck at the module level (global)
# This is necessary so the drawCard() and hit() functions work as written.
deck = []

def createDeck():
    suits = ["Diamonds", "Hearts", "Clubs", "Spades"]
    values = ["Ace", "2", "3", "4", "5", "6", "7", "8", "9", "10", "Jack", "Queen", "King"]
    # just a loop that takes every number and adds it to the deck alongisde each suit
    initial_deck = [f"{value} of {suit}" for value in values for suit in suits]
    # we create 4 decks
    deck = initial_deck * 4
    return deck


def shuffleDeck(deck_to_shuffle, serverseed, clientseed, nonce):
    """
    Shuffles the deck using a provably fair Fisher-Yates algorithm
    based on the server seed, client seed, and nonce.
    """
    message = f"{clientseed}-{nonce}".encode('utf-8')
    h = hmac.HMAC(serverseed, hashes.SHA512())
    h.update(message)
    hex_hash = h.finalize().hex()
    
    shuffled_deck = deck_to_shuffle[:]
    deck_size = len(shuffled_deck)
    
    # Implementation of fisher-yates shuffling algorithm
    for i in range(deck_size - 1, 0, -1):
        if len(hex_hash) < 4:
            h_new = hmac.HMAC(serverseed, hashes.SHA512())
            h_new.update(hex_hash.encode('utf-8')) # Use the remainder
            hex_hash += h_new.finalize().hex()
        
        hex_chunk = hex_hash[:4]
        hex_hash = hex_hash[4:]
        
        shuffleNum = int(hex_chunk, 16)
        shuffleNum = shuffleNum % (i + 1)
        
        shuffled_deck[i], shuffled_deck[shuffleNum] = shuffled_deck[shuffleNum], shuffled_deck[i]

    return shuffled_deck


def drawCard():
    global deck
    # We get the card on top of the deck (end of the list)
    if not deck:
        print("Reshuffling the deck...")
        deck = createDeck()
        # In a real scenario, you'd re-shuffle with new seeds, but for this
        # simple version, we'll just re-create.
        # For a provably fair system, you'd need a new shuffle here.
        # For now, we'll just repopulate.
    
    card = deck.pop()
    return card


def hit(hand):
    hand.append(drawCard())

def calculateValue(hand):
    value = 0
    aces = 0
    blackjack = False
    card_values = {"2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9, "10": 10, "Jack": 10, "Queen": 10,
                   "King": 10}
    
    for card in hand:
        val = card.split(" ")[0]
        if val == "Ace":
            aces = aces + 1
        else:
            value += card_values[val]

    value = value + aces * 11
    
    # A Blackjack (3:2 payout) only happens on the first two cards
    if value == 21 and len(hand) == 2:
        blackjack = True
        return value, aces, blackjack

    # Handle busts if aces are present
    while value > 21 and aces > 0:
        value -= 10
        aces -= 1
        
    return value, aces, blackjack

def winCheck(playerVal, dealerVal, blackjack, blackjackDealer):
    """
    Returns:
    1 = Player Win
    2 = Player Lose
    3 = Push (Tie)
    4 = Player Blackjack (3:2 payout)
    """
    if playerVal > 21:
        return 2 # Player busts

    if dealerVal > 21:
        return 1 # Dealer busts

    # Handle Blackjacks first
    if blackjack and not blackjackDealer:
        return 4 # Player BJ
    if blackjackDealer and not blackjack:
        return 2 # Dealer BJ
    if blackjack and blackjackDealer:
        return 3 # Both BJ

    # Standard value comparison
    if playerVal > dealerVal:
        return 1
    elif dealerVal > playerVal:
        return 2
    else: # playerVal == dealerVal
        return 3

def play_one_hand(current_balance_float, server_seed, client_seed, nonce):
    global deck
    blackjackDealer = False
    blackjackPlayer = False
    
    # --- Bet Validation ---
    while True:
        try:
            bet_str = input(f"\nYour balance: {current_balance_float}. How much to bet? (0 to quit hand): ")
            bet = float(bet_str)
            if bet == 0:
                return current_balance_float # User quits hand
            if bet < 0:
                print("Bet must be positive.")
            elif bet > current_balance_float:
                print("Insufficient funds.")
            else:
                break # Valid bet
        except ValueError:
            print("Please enter a valid number.")

    playerHand = []
    dealerHand = []
    
    print("Shuffling deck for this hand...")
    # A full deck is created and shuffled for *each hand*
    deck_for_hand = createDeck()
    deck = shuffleDeck(deck_for_hand, server_seed, client_seed, nonce)
    
    # --- Deal Cards
    playerHand.append(drawCard())
    dealerHand.append(drawCard()) # Dealer's down card
    playerHand.append(drawCard())
    dealerHand.append(drawCard()) # Dealer's up card
    
    dealerCardUp = dealerHand[1] # The second card is the up card

    (playerVal, aces, blackjackPlayer) = calculateValue(playerHand)
    # We only calculate the dealer's *up card* value initially
    (dealerUpVal, _, _) = calculateValue([dealerCardUp])

    print(f"\n--- Your Hand ({playerVal}) ---")
    for item in playerHand:
        print(item)
    print(f"\n--- Dealer's Hand ({dealerUpVal}) ---")
    print(f"{dealerCardUp}")
    print("[Hidden Card]")

    # --- Player's Turn
    stand = False
    if blackjackPlayer:
        print("Blackjack!")
        stand = True
    
    while playerVal < 22 and not stand:
        action = ""
        while action not in ['h', 's']:
            action = input("Do you want to Hit or Stand? (H/S): ").strip().lower()

        if action == "h":
            hit(playerHand)
            (playerVal, aces, _) = calculateValue(playerHand) # BJ only on first 2
            print(f"\n--- Your Hand ({playerVal}) ---")
            for item in playerHand:
                print(item)
        else:
            stand = True
    
    if playerVal > 21:
        print(f"Bust! You have {playerVal}.")

    # --- Dealer's Turn
    # Only proceed if player hasn't bust
    if playerVal <= 21:
        print("\n--- Dealer's Turn ---")
        (dealerVal, acesDealer, blackjackDealer) = calculateValue(dealerHand)

        print(f"Dealer's Full Hand ({dealerVal}):")
        for item in dealerHand:
            print(item)

        # Rule: Dealer hits on soft 17
        is_soft_17 = (dealerVal == 17 and acesDealer > 0)
        
        while dealerVal < 17 or is_soft_17:
            print("Dealer hits...")
            hit(dealerHand)
            (dealerVal, acesDealer, _) = calculateValue(dealerHand)
            
            print(f"Dealer's New Hand ({dealerVal}):")
            for item in dealerHand:
                print(item)
            
            # Re-check soft 17 status
            is_soft_17 = (dealerVal == 17 and acesDealer > 0)
        
        if dealerVal > 21:
            print(f"Dealer Busts with {dealerVal}!")
    else:
        # Player bust, dealer doesn't need to play
        # We still get their value for the winCheck
        (dealerVal, acesDealer, blackjackDealer) = calculateValue(dealerHand)



    game_result = winCheck(playerVal, dealerVal, blackjackPlayer, blackjackDealer)
    
    new_balance = current_balance_float
    if game_result == 1: # Player wins
        print(f"You win! Your value: {playerVal}, Dealer: {dealerVal}")
        new_balance += bet
    elif game_result == 2: # Player loses
        print(f"You lose. Your value: {playerVal}, Dealer: {dealerVal}")
        new_balance -= bet
    elif game_result == 3: # Push
        print(f"Push (Tie). Your value: {playerVal}, Dealer: {dealerVal}")
        # new_balance is unchanged
    elif game_result == 4: # Player Blackjack
        print("Blackjack! You win 1.5x your bet!")
        new_balance += (bet * 1.5)

    print(f"\nYour new balance is: {new_balance}")
    
    return new_balance

def play_blackjack_game(current_balance):
    print("--- Welcome to Blackjack ---")
    
    if current_balance <= 0:
        print(f"Your balance is {current_balance}. You cannot play.")
        return current_balance

    server_seed_session = os.urandom(16)
    client_seed_session = input("Introduce your client seed for this session: ")
    nonce = 0 # Nonce increments each hand

    playing = True
    while playing:
        if current_balance <= 0:
            print("You've run out of money! Returning to main menu.")
            break # Exit the while loop
            
        nonce += 1 # Increment nonce for the new hand
        print(f"\n--- Starting Hand #{nonce} ---")
        
        # Pass the session seeds and the new nonce to the hand
        current_balance = play_one_hand(current_balance, server_seed_session, client_seed_session, nonce)
        
        # After the hand, we show the seeds for verification
        print(f"\n--- Provably Fair (Verification for Hand #{nonce}) ---")
        print(f"Server Seed (hex): {server_seed_session.hex()}")
        print(f"Client Seed: {client_seed_session}")
        print(f"Nonce: {nonce}")
        print("You can verify this result externally using an HMAC_SHA512 calculator.")

        if current_balance <= 0:
            print("\nYou've run out of money! Returning to main menu.")
            break
        
        play_again = ""
        while play_again not in ['y', 'n']:
            play_again = input("\nPlay another hand? (Y/N): ").strip().lower()
        
        if play_again == 'n':
            playing = False # Exit the while loop

    print("Thanks for playing! Returning to main menu.")
    return current_balance # Return the final balance to main_menu
