import random
from app.models.user_model import User
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional  # Add this import

def generate_nickname_with_id(session: Optional[AsyncSession] = None, user_id: str = "default_user_id") -> str:
    """Generate a URL-safe nickname using adjectives, animal names, and append the user ID."""
    adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
    animals = ["panda", "fox", "raccoon", "koala", "lion"]
    number = random.randint(0, 999)
    base_nickname = f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"

    # Check if the base nickname is unique, append user_id if not.
    unique_nickname = base_nickname
    retries = 0
    max_retries = 10  # Retry limit to prevent infinite loop
    
    if session:
        while session.query(User).filter(User.nickname == unique_nickname).count() > 0 and retries < max_retries:
            retries += 1
            unique_nickname = f"{base_nickname}_{user_id}"

    if retries == max_retries:
        raise ValueError("Unable to generate a unique nickname after several retries.")

    return unique_nickname
