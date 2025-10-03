const express=require('express');
const app=express();
const http=require('http');
const {Server}=require('socket.io');
const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const cors=require('cors');

require('dotenv').config();

app.use(express.json());
app.use(cors());
const server=http.createServer(app);
const io=new Server(server,{
    cors:{
        origin:"*",
        methods:["GET","POST","PUT","DELETE"]
    }
})

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("MongoDB connected"))
.catch((err)=>console.log("mongoDB connection error:",err));

const userschema=new mongoose.Schema({
    username:{type:String,required:true,unique:true},
    email:{type:String,required:true,unique:true},
    password:{type:String,required:true}
});

const user=mongoose.model('user',userschema);

const projectschema=new mongoose.Schema({
    name:{type:String,required:true},
    code:{type:String,default:""},
    owner:{type:mongoose.Schema.Types.ObjectId,ref:'user'},
},{timestamps:true});

const project =mongoose.model('project',projectschema);

function auth(req,res,next){
    const authheader=req.headers['authorization'];
    if(!authheader) return res.status(401).json({message:"no token"});

    const token=authheader.split(' ')[1];
    if(!token) return res.status(401).json({message:"invalid token"});

    jwt.verify(token,process.env.JWT_SECRET,(err,user)=>{
        if(err) return res.status(403).json({message:"token  not valid"});
        req.user=user;
        next();
    });
}

//routes
app.get("/",(req,res)=>{
    res.send("<collabco> backend is running...");
});

app.post("/api/register",async(req,res)=>{
    try{
        const {username,email,password}=req.body;
        const existing=await user.findOne({email});
        if(existing) return res.status(400).json({message:"user already exists"});

        const hashedpassword=await bcrypt.hash(password,10);
        const newuser=new user({username,email,password:hashedpassword});
        await newuser.save();
        
        const token=jwt.sign({id:newuser._id},process.env.JWT_SECRET,{expiresIn:"1h"});
        res.status(201).json({
            message:"user created successfully", 
            token, 
            username: newuser.username, 
            userId: newuser._id
        });
    }
    catch(err){
        res.status(500).json({message:"server error"});
    }
});

app.post("/api/login",async(req,res)=>{
    try{
        const{email,password}=req.body;
        const users=await user.findOne({email});
        if(!users) return res.status(400).json({message:"user not found"});

        const isvalid=await bcrypt.compare(password,users.password);
        if(!isvalid) return res.status(400).json({message:"invalid credentials"});

        const token=jwt.sign({id:users._id},process.env.JWT_SECRET,{expiresIn:"1h"});
        res.status(200).json({
            token, 
            username: users.username, 
            userId: users._id
        });
    }
    catch(err){
        res.status(500).json({message:"server error"});
    }
});
app.get("/api/user/me", auth, async(req, res) => {
    try {
        console.log("Fetching user info for ID:", req.user.id);
        const userDoc = await user.findById(req.user.id).select('-password');
        if (!userDoc) return res.status(404).json({message: "user not found"});
        
        res.status(200).json({
            userId: userDoc._id,
            id: userDoc._id,
            username: userDoc.username,
            email: userDoc.email
        });
    } catch(err) {
        console.error("Error fetching user info:", err);
        res.status(500).json({message: "server error"});
    }
});

app.post("/api/projects",auth,async(req,res)=>{
    try{
        const{name,code}=req.body;
        const newproject=new project({name,code,owner:req.user.id});
        await newproject.save();
        res.status(201).json({
            message:"project created successfully",
            project:newproject,
            _id: newproject._id
        });
    }
    catch(err){
        console.error("Error creating project:", err);
        res.status(500).json({message:"server error"});
    }
});

app.put("/api/projects/:id",auth,async(req,res)=>{
    try{
        const{id}=req.params;
        const{code}=req.body;
        const projects=await project.findById(id);
        if(!projects) return res.status(404).json({message:"project not found"});
        if(projects.owner.toString()!==req.user.id) return res.status(403).json({message:"unauthorized"});

        projects.code=code;
        await projects.save();
        res.status(200).json({message:"project updated successfully",project:projects});
    }
    catch(err){
        res.status(500).json({message:"server error"});
    }
})

app.get("/api/projects",auth,async(req,res)=>{
    try{
        const projects=await project.find({owner:req.user.id});
        res.status(200).json({projects});
    }
    catch(err){
        res.status(500).json({message:"server error"});
    }
});

app.get("/api/projects/:id",auth,async(req,res)=>{
    try{
        const {id} = req.params;
        console.log("Fetching project with ID:", id);
        console.log("User ID from token:", req.user.id);
        
        const projects = await project.findById(id);
        if(!projects) {
            console.log("Project not found with ID:", id);
            return res.status(404).json({message:"project not found"});
        }
        
        console.log("Project owner:", projects.owner.toString());
        console.log("Current user:", req.user.id);
        
        res.status(200).json({
            project: projects,
            _id: projects._id,
            owner: projects.owner
        });
    }
    catch(err){
        console.error("Error fetching project:", err);
        res.status(500).json({message:"server error"});
    }
});

app.delete("/api/projects/:id",auth,async(req,res)=>{
    try{
        const{id}=req.params;
        const projects=await project.findById(id);
        if(!projects) return res.status(404).json({message:"project not found"});
        if(projects.owner.toString()!=req.user.id) return res.status(403).json({message:"unauthorized"});

        await projects.deleteOne();
        res.status(200).json({message:"project deleted successfully"});
    }
    catch(err){
        res.status(500).json({message:"server error"});
    }
});

//io connection
io.on("connection",(socket)=>{
    console.log("⚡ user connected:",socket.id);

    //joining room
    socket.on("joinproject", async ({projectId,username})=>{
        socket.join(projectId);
        try {
            const currentProject = await project.findById(projectId);
            if (currentProject && currentProject.code) {
              
                socket.emit("receivecode", { code: currentProject.code });
                console.log(`Sent current code to ${username} joining project: ${projectId}`);
            }
        } catch (err) {
            console.error("Error loading project code:", err);
        }
        
        socket.to(projectId).emit("userjoined",{username, id: socket.id});
        console.log(`${username} joined project: ${projectId}`);
    });

    
  //handling code
socket.on("codechange",({projectId,code})=>{
    socket.to(projectId).emit("receivecode",{code});
});

    //chat 
    socket.on("chatmessage",({projectId,username,message})=>{
        io.to(projectId).emit("receivemessage",{username,message,time:new Date().toISOString()});
    });

    //cursor 
    socket.on("cursorchange",({projectId,username,position})=>{
        socket.to(projectId).emit("receivecursor",{username,position});
    });

    //suggestion
    socket.on("suggestion",({projectId,username,suggestion})=>{
        // Send to all clients except the sender to avoid duplicate suggestions
        socket.to(projectId).emit("receivesuggestion",{username,suggestion,time:new Date().toISOString()});
    });

    //disconnect
    socket.on("disconnect",()=>{
        console.log("❌ user disconnected",socket.id);
    });
});

const PORT=process.env.PORT||3000;
server.listen(PORT,'0.0.0.0',()=>{
    console.log(`server running on port ${process.env.PORT||3000}`);
});
