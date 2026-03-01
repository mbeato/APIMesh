// Types for user input (loosely based on OpenAPI 3.0)
interface Parameter {
  name: string;
  in: "query" | "path" | "header" | "cookie";
  required?: boolean;
  description?: string;
  schema?: any;
}

interface RequestBody {
  description?: string;
  required?: boolean;
  content: {
    [media: string]: {
      schema: any;
      example?: any;
    }
  }
}

interface ResponseObject {
  description: string;
  content?: {
    [media: string]: {
      schema: any;
      example?: any;
    }
  };
}

interface GenerateSwaggerInput {
  path: string;
  method: string; // e.g. GET, POST, PUT, DELETE, etc.
  summary: string;
  description?: string;
  parameters?: Parameter[];
  requestBody?: RequestBody;
  responses?: {
    [status: string]: ResponseObject;
  };
  tags?: string[];
}

// Helper validation function
function validateInput(obj: any): asserts obj is GenerateSwaggerInput {
  if (typeof obj !== "object" || !obj) throw Object.assign(new Error("Invalid payload"), { status: 400 });
  if (!obj.path || typeof obj.path !== "string" || !obj.path.startsWith("/")) {
    throw Object.assign(new Error("Missing or invalid 'path'. Must start with /"), { status: 400 });
  }
  if (!obj.method || typeof obj.method !== "string") {
    throw Object.assign(new Error("Missing or invalid 'method'"), { status: 400 });
  }
  if (!obj.summary || typeof obj.summary !== "string") {
    throw Object.assign(new Error("Missing or invalid 'summary'"), { status: 400 });
  }
  // Optionals can be omitted
}

export function generateSwagger(user: any): any {
  validateInput(user);
  const {
    path,
    method,
    summary,
    description,
    parameters,
    requestBody,
    responses,
    tags
  } = user as GenerateSwaggerInput;

  const requestBodyOut = requestBody
    ? {
      description: requestBody.description || "Request body",
      required: !!requestBody.required,
      content: requestBody.content || { "application/json": { schema: {} } }
    }
    : undefined;
  
  // Reasonable default response
  const defaultResponses = {
    "200": {
      description: "Success"
    },
    "400": {
      description: "Bad Request"
    }
  };

  const lowerMethod = method.toLowerCase();
  const pathObj: any = {
    [lowerMethod]: {
      summary,
      description: description || summary,
      parameters: Array.isArray(parameters) && parameters.length > 0 ? parameters : undefined,
      requestBody: requestBodyOut,
      responses: responses && Object.keys(responses).length > 0 ? responses : defaultResponses,
      tags: Array.isArray(tags) && tags.length > 0 ? tags : undefined
    }
  };

  // OpenAPI top-level document
  const swaggerDoc = {
    openapi: "3.0.3",
    info: {
      title: `Swagger Docs for ${path}`,
      description: description || summary,
      version: "1.0.0"
    },
    paths: {
      [path]: pathObj
    }
  };
  return swaggerDoc;
}
