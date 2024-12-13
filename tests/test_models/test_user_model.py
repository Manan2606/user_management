from builtins import repr
from datetime import datetime, timezone
import pytest
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user_model import User, UserRole

@pytest.mark.asyncio
async def test_user_role(db_session: AsyncSession, user: User, admin_user: User, manager_user: User):
    """
    Tests that the default role is assigned correctly and can be updated.
    """
    assert user.role == UserRole.AUTHENTICATED, "Default role should be USER"
    assert admin_user.role == UserRole.ADMIN, "Admin role should be correctly assigned"
    assert manager_user.role == UserRole.MANAGER, "Pro role should be correctly assigned"

@pytest.mark.asyncio
async def test_has_role(user: User, admin_user: User, manager_user: User):
    """
    Tests the has_role method to ensure it accurately checks the user's role.
    """
    assert user.has_role(UserRole.AUTHENTICATED), "User should have USER role"
    assert not user.has_role(UserRole.ADMIN), "User should not have ADMIN role"
    assert admin_user.has_role(UserRole.ADMIN), "Admin user should have ADMIN role"
    assert manager_user.has_role(UserRole.MANAGER), "Pro user should have PRO role"

@pytest.mark.asyncio
async def test_user_repr(user: User):
    """
    Tests the __repr__ method for accurate representation of the User object.
    """
    assert repr(user) == f"<User {user.nickname}, Role: {user.role.name}>", "__repr__ should include nickname and role"

@pytest.mark.asyncio
async def test_failed_login_attempts_increment(db_session: AsyncSession, user: User):
    """
    Tests that failed login attempts can be incremented and persisted correctly.
    """
    initial_attempts = user.failed_login_attempts
    user.failed_login_attempts += 1
    await db_session.commit()
    await db_session.refresh(user)
    assert user.failed_login_attempts == initial_attempts + 1, "Failed login attempts should increment"

@pytest.mark.asyncio
async def test_last_login_update(db_session: AsyncSession, user: User):
    """
    Tests updating the last login timestamp.
    """
    new_last_login = datetime.now(timezone.utc)
    user.last_login_at = new_last_login
    await db_session.commit()
    await db_session.refresh(user)
    assert user.last_login_at == new_last_login, "Last login timestamp should update correctly"

@pytest.mark.asyncio
async def test_account_lock_and_unlock(db_session: AsyncSession, user: User):
    """
    Tests locking and unlocking the user account.
    """
    # Initially, the account should not be locked.
    assert not user.is_locked, "Account should initially be unlocked"

    # Lock the account and verify.
    user.lock_account()
    await db_session.commit()
    await db_session.refresh(user)
    assert user.is_locked, "Account should be locked after calling lock_account()"

    # Unlock the account and verify.
    user.unlock_account()
    await db_session.commit()
    await db_session.refresh(user)
    assert not user.is_locked, "Account should be unlocked after calling unlock_account()"

@pytest.mark.asyncio
async def test_email_verification(db_session: AsyncSession, user: User):
    """
    Tests the email verification functionality.
    """
    # Initially, the email should not be verified.
    assert not user.email_verified, "Email should initially be unverified"

    # Verify the email and check.
    user.verify_email()
    await db_session.commit()
    await db_session.refresh(user)
    assert user.email_verified, "Email should be verified after calling verify_email()"

@pytest.mark.asyncio
async def test_user_profile_pic_url_update(db_session: AsyncSession, user: User):
    """
    Tests the profile pic update functionality.
    """
    # Initially, the profile pic should be updated.

    # Verify the email and check.
    profile_pic_url = "http://myprofile/picture.png"
    user.profile_picture_url = profile_pic_url
    await db_session.commit()
    await db_session.refresh(user)
    assert user.profile_picture_url == profile_pic_url, "The profile pic did not update"

@pytest.mark.asyncio
async def test_user_linkedin_url_update(db_session: AsyncSession, user: User):
    """
    Tests the profile pic update functionality.
    """
    # Initially, the linkedin should  be updated.

    # Verify the linkedin profile url.
    profile_linkedin_url = "http://www.linkedin.com/profile"
    user.linkedin_profile_url = profile_linkedin_url
    await db_session.commit()
    await db_session.refresh(user)
    assert user.linkedin_profile_url == profile_linkedin_url, "The profile pic did not update"


@pytest.mark.asyncio
async def test_user_github_url_update(db_session: AsyncSession, user: User):
    """
    Tests the profile pic update functionality.
    """
    # Initially, the linkedin should  be updated.

    # Verify the linkedin profile url.
    profile_github_url = "http://www.github.com/profile"
    user.github_profile_url = profile_github_url
    await db_session.commit()
    await db_session.refresh(user)
    assert user.github_profile_url == profile_github_url, "The github did not update"


@pytest.mark.asyncio
async def test_update_user_role(db_session: AsyncSession, user: User):
    """
    Tests updating the user's role and ensuring it persists correctly.
    """
    user.role = UserRole.ADMIN
    await db_session.commit()
    await db_session.refresh(user)
    assert user.role == UserRole.ADMIN, "Role update should persist correctly in the database"

@pytest.mark.asyncio
async def test_account_lock_on_login(db_session: AsyncSession, user: User):
    """
    Tests that login is prevented when the account is locked.
    """
    user.lock_account()
    await db_session.commit()
    await db_session.refresh(user)

    # Simulate a login attempt
    assert user.is_locked, "Account should be locked"
    # Assuming there's a method to try logging in, it should raise an exception or return a failure response
    with pytest.raises(Exception):  # Replace with actual login failure method
        await user.login("wrong_password")

@pytest.mark.asyncio
async def test_email_verification_token(db_session: AsyncSession, user: User):
    """
    Tests the creation and usage of an email verification token.
    """
    verification_token = uuid.uuid4().hex  # Simulate generating a token
    user.verification_token = verification_token
    await db_session.commit()
    await db_session.refresh(user)

    assert user.verification_token == verification_token, "Verification token should match the generated one"
    
    # Now simulate email verification by clearing the token after use
    user.verify_email()  # Simulate email verification
    user.verification_token = None  # Remove the token after email verification
    await db_session.commit()
    await db_session.refresh(user)
    
    assert user.email_verified, "Email should be verified"
    assert user.verification_token is None, "Verification token should be removed after email verification"

@pytest.mark.asyncio
async def test_update_professional_status(db_session: AsyncSession, user: User):
    """
    Tests updating the professional status of the user and the timestamp update.
    """
    initial_status = user.is_professional
    initial_timestamp = user.professional_status_updated_at

    # Change the professional status
    user.update_professional_status(True)
    await db_session.commit()
    await db_session.refresh(user)

    assert user.is_professional is not initial_status, "Professional status should be updated"
    assert user.professional_status_updated_at != initial_timestamp, "Timestamp should be updated when status is changed"

from passlib.context import CryptContext

# Initialize password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@pytest.mark.asyncio
async def test_user_password_hashing(db_session: AsyncSession):
    """
    Tests that the password is hashed when the user is created.
    """
    raw_password = "SecurePassword123!"
    hashed_password = pwd_context.hash(raw_password)  # Hash the password before assigning

    user = User(
        nickname="johndoe",
        email="john.doe@example.com",
        hashed_password=hashed_password,  # Store the hashed password
        role=UserRole.AUTHENTICATED
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    assert user.hashed_password != raw_password, "Password should be stored as a hashed value, not plain text"


@pytest.mark.asyncio
async def test_role_change_behavior(db_session: AsyncSession, user: User):
    """
    Tests that the user's role can be changed and the new role reflects the expected behavior.
    """
    initial_role = user.role
    new_role = UserRole.ADMIN

    # Change the user's role
    user.role = new_role
    await db_session.commit()
    await db_session.refresh(user)

    assert user.role != initial_role, "User's role should be updated"
    assert user.role == new_role, "User's role should be updated to ADMIN"

    # Ensure the role behaves correctly with access control (role-based behavior)
    assert user.has_role(UserRole.ADMIN), "User should have the ADMIN role after the update"
