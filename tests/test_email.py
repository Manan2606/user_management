import pytest
from app.services.email_service import EmailService
from app.utils.template_manager import TemplateManager
from unittest.mock import AsyncMock

    
@pytest.mark.asyncio
async def test_send_markdown_email(email_service):
    user_data = {
        "email": "test@example.com",
        "name": "Test User",
        "verification_url": "http://example.com/verify?token=abc123"
    }
    await email_service.send_user_email(user_data, 'email_verification')
    # Manual verification in Mailtrap

@pytest.mark.asyncio
async def test_send_user_email_invalid_email_type(email_service):
    # Mocking the TemplateManager
    template_manager = AsyncMock(spec=TemplateManager)
    email_service = EmailService(template_manager)

    # Define invalid email type
    invalid_email_type = "invalid_email_type"

    # User data for testing
    user_data = {
        "email": "test@example.com",
        "name": "Test User",
        "verification_url": "http://example.com/verify?token=abc123"
    }

    # Check that ValueError is raised for invalid email type
    with pytest.raises(ValueError, match="Invalid email type"):
        await email_service.send_user_email(user_data, invalid_email_type)