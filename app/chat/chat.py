from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from openai import OpenAI
import os
import json
from dotenv import load_dotenv
from schemas.chat import ChatRequest
from schemas.response import APIResponse

# Load environment variables
load_dotenv()

# Initialize router
router = APIRouter( tags=["chat"])

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("DEEPSEEK_API_KEY"), base_url="https://api.deepseek.com")

# System prompts
SYSTEM_MESSAGES = [
    {"role": "system", "content": "You are my girlfriend."},
    {"role": "system", "content": "Keep your responses under 10 words maximum."},
    {"role": "system", "content": "Be conversational and engaging."},
    {"role": "system", "content": "Always provide direct, concise answers."}
]

@router.post("/stream")
async def chat_stream(request: ChatRequest):
    """
    Chat endpoint with Server-Sent Events streaming
    """
    try:
        # Convert Pydantic models to dict format
        messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]
        
        # Combine system messages with user messages
        all_messages = SYSTEM_MESSAGES + messages
        
        def generate():
            try:
                # Create streaming response
                stream = client.chat.completions.create(
                    model="deepseek-chat",
                    messages=all_messages,
                    stream=True
                )
                
                # Stream each chunk
                for chunk in stream:
                    if chunk.choices[0].delta.content is not None:
                        content = chunk.choices[0].delta.content
                        # Format as SSE
                        yield f"data: {json.dumps({'content': content, 'done': False})}\n\n"
                
                # Send completion signal
                yield f"data: {json.dumps({'content': '', 'done': True})}\n\n"
                
            except Exception as e:
                # Send error as SSE
                yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"
        
        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "status": "fail",
                "message": f"Streaming chat request failed: {str(e)}",
                "data": None
            }
        )

@router.post("/", response_model=APIResponse)
async def chat_normal(request: ChatRequest):
    """
    Regular chat endpoint without streaming
    """
    try:
        # Convert Pydantic models to dict format
        messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]
        
        # Combine system messages with user messages
        all_messages = SYSTEM_MESSAGES + messages
        
        # Get response
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=all_messages,
            stream=False
        )
        
        return APIResponse(
            status="success",
            message="Chat response generated successfully",
            data={
                "response": response.choices[0].message.content,
                "usage": response.usage.dict() if response.usage else None
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={
                "status": "fail",
                "message": f"Chat request failed: {str(e)}",
                "data": None
            }
        )
