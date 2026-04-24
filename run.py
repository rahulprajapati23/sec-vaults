import os
import uvicorn

if __name__ == "__main__":
    # Railway automatically injects the PORT environment variable.
    # We read it natively in Python to avoid shell expansion issues.
    port = int(os.environ.get("PORT", 8000))
    
    print(f"Starting server on 0.0.0.0:{port}")
    
    uvicorn.run(
        "app.main:app", 
        host="0.0.0.0", 
        port=port, 
        proxy_headers=True, 
        forwarded_allow_ips="*"
    )
