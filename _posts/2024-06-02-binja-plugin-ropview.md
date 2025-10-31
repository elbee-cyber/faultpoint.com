---
title: "Tool Release: RopView"
date: 2024-06-02
description: "A technical post on my new gadget analysis framework."
tag: ["unicorn","pandas","emulation","tool"]
categories: ["Emulation","Tool"]
image: /assets/posts/2024-06-02/semantic_search_demo.gif
---

Technical explanations and concepts of RopView, a plugin made for BinaryNinja that does gadget analysis. This blog post describes the technical components of [this tool](https://github.com/elbee-cyber/RopView). Since the time of writing analysis prestates and presets have been added, along with support for the following architecutres: i386, amd64, armv7, aarch64, thumb2 (toggle),mipsel32, mipsel64, mips32, mips64.
<!--more-->

# Table of contents
1. [Foreword](#foreword)
2. [Design and Components](#design)
3. [Compatibility](#compatibility)
4. [Gadget Discovery](#discovery)
5. [Gadget Analyzer](#analysis)
   1. [Initialization](#analysis-initialization)
   2. [Realtime Contextualizing](#analysis-context)
   3. [Step-thru Analysis](#analysis-stepthru)
6. [Semantic Search Filter](#search)
7. [Closing](#closing)

![](/assets/posts/2024-06-02/logo.png)

<a name="foreword"></a>
### Foreword
I recently published a plugin for BinaryNinja called RopView, a gadget analysis framework that integrates emulation into ROP searching, visualizing memory side effects. For some time now, I've been meaning to both develop a tool capable of this, but also contribute another plugin for the BinaryNinja community and found this project to be an excellent way to do both. During the entire development process, considering what would make the exploit developer's life easier was at the forefront, because I myself wanted to make this something I would use over similar tools when building ROP chains and could easily incorporate into my workflow. What makes RopView different from other return-oriented-programming tools however, is not its interfacing with BinaryNinja's BinaryView. That honor goes to its powerful gadget analysis and search engine framework, which operate in consort.

<a name="design"></a>
### Design and Components
RopView is a visual UI plugin that is registered as an additional BinaryView for the current session. The layout of the plugin involves a tab system with a search filter, which remains accessible from any selected tab. The first tab, which is where the majority of time will likely be spent, is the gadget analysis display. It is made of two panes, a gadget pane, and a focused analysis pane. The gadget pane will display the entire gadget pool with user-specified filters and options applied, or gadgets that service a search request. Under the hood, the gadget pane is a QTreeWidget with scrollable items (via tab or arrow-key navigation). Additionally, double clicking on a selected gadget will navigate to its address in the primary linear BinaryView. Effects of the currently selected gadget are rendered in the analysis pane.

Analysis reports consider three focal points (only effected/clobbered memory is analyzed in each):
- Start state (Before analysis)
  - Effects before gadget executes
- Instruction states (During analysis)
  - Effects after each instruction in the gadget
- End state (After analysis)
  - The memory state the gadget leaves behind

![](/assets/posts/2024-06-02/sc1.png)

Analysis is done through gadget emulation and certain algorithmic decisions were made in order to make the emulation as fast as possible. Moreover, analysis details are saved as 'GadgetAnalysis' objects, which contain the prestate, step-states, and end-state tied to a gadget address. These objects are cached and used both to resolve an analysis report if a gadget is re-selected and to assist in semantic search functionality. More technical details relevant to the analyzer itself—which will likely be the most interesting aspect of this post—will be discussed later in the relevant section.

In between the main window and the search box are two status boxes which display the gadget count (tied to the GadgetPane which could be the full pool or search results) and the search status (success or failure). The second tab contains a chain builder, which was originally going to be included with the first release, but due to certain constraints and focus on the primary functionalities, was not. In the future, gadgets from the GadgetPane will be able to be added and ordered in a list on this pane, which you can then choose or create custom script presets for.

The last tab includes configurable settings for both the standard gadget search and analysis prestates. Here register prestates can be explicitly defined and these will be used for all further analysis and semantic searches. Ideally, you'd set the registers you care about to their correct values at the time of controlled execution and further analysis will more accurately reflect what gadgets matter to you given your situation. The only other option which is out of the ordinary is the semantic depth option, which directs how many gadgets deep a query should explore for serviceable gadgets.

![](/assets/posts/2024-06-02/sc2.png)

One of the largest components, which I will briefly talk about but not get deep into because it is uninteresting, is the GadgetRenderer. This pane is responsible for repooling (if an option is changed such as depth, which affects the initial gadget pool) or sorting the current pool (options like bad bytes or duplicates). No matter the caller of GadgetRender, it will always consider the current configuration context when initiating and rendering a GadgetSearch. Speaking of which, the GadgetRender does, and obviously so, have a lot of call sites from various components within the tool.

<a name="compatibility"></a>
### Compatibility
Currently this tool only supports i386 and amd64 architectures and an assert needs to be passed for the tool to be successfully initialized. Adding support for ARM and MIPS is one of the most prominent features I'd like to include in the future and will likely be the first thing worked on in future development. Obviously, as a store/load architecture many different components will have to be added to support this and it won't be as simple as an update to the tool's constants. For instance, delay slots will need to be considered in gadget exploration as well as how gadget searches are done entirely as both are constant-sized 4 byte instruction sets. Additionally, more gadget querying options would be ideal for both (e.g., for MIPS, queries for stackfinders, li a0, double jumps, etc.). The largest component that will need to be reworked is the GadgetSearch. What would likely require the least reconfiguration would be the GadgetAnalysis, which does diffing and analysis purely based on memory states and does not rely on static checks or heuristics.

<a name="discovery"></a>
### Gadget Discovery (What exactly IS a gadget?)
That stuff was boring and necessary to give a high-level overview of the tool's primary functionality and design. Now onto the more interesting stuff: actually dealing with gadgets. As mentioned earlier, this tool does everything in-house and does not rely on a third party for actually finding and loading gadgets. Gadget discovery is the first task run by the GadgetRender during initialization and is responsible for finding gadgets within the current BinaryView's data. The algorithm I am about to talk about for doing gadget searching is specifically tied to the x86 instruction set; different considerations have to be taken for instruction sets like MIPS, as what dictates gadgets differs entirely.

This section will be a valuable part of this post, as rarely do I see people actually talk about gadget searching and how we do it. Additionally, it seems like people who are just dipping their toes into binary exploitation sometimes just blindly return to addresses that do things and don't actually understand, "what makes a gadget?". We'll address both of these concepts here. Gadgets in x86 (and any language for that matter) are simple. For x86, a gadget is defined as any address you can return to that decodes to a valid group of instructions and ends with an instruction that lets you control execution flow. Unlike RISC architectures, x86 instructions are not a fixed size; they can be anywhere between 1 and 16 bytes. This matters because it essentially increases the pool of candidate gadgets since you can return to misaligned addresses and walk backwards any n number of bytes and, in a sense, create code that isn't actually user-defined.

![](/assets/posts/2024-06-02/sc3.png)
![](/assets/posts/2024-06-02/sc4.png)

The GadgetSearch algorithm searches the binary for potential gadget sites (using regex matching) and then walks back n number of bytes (defined by depth) checking at each step if a gadget exists (valid decoding occurred). It does this until the depth is reached or a gadget-violating condition occurs such as the control instruction no longer existing or a multi-branch. This algorithm also utilizes the BinaryView's session data to cache all gadgets, which GadgetSearch will use in the future to resolve gadgets instead of searching again (unless an option change violates the accuracy of the current gadget pool and a flush is required).

Below is a pseudo snippet of the code responsible:

```python
# Ctrl is an architecture-tied constant in the following structure:
# (start constant, inst_len, inst regex, inst_type)
# ie: (b'\xff',2,b'\xff[\x10\x11\x12\x13\x16\x17]','call') for "call [reg]" control instruction
for ctrl in self.__control_insn:
    # Start search at base each time
    curr_site = self.__bv.start

    while curr_site is not None:
        # Find potential gadget site
        curr_site = self.__bv.find_next_data(curr_site, ctrl[0])
        if curr_site is None:
            break
        # Saved to find next search site after depth search
        save = curr_site
        # Confirm gadget site using regex match
        if re.match(ctrl[2], self.__bv.read(curr_site, ctrl[1])) is not None:
            # Depth search for gadgets and subgadgets
            for i in range(0, self.depth):
                if not self.__bv.get_segment_at(curr_site).executable:
                    break
                else:
                    curr_site = save - i
                    check_for_insn = self.__bv.read(curr_site, i + ctrl[1])
                    '''
                    Checks for gadget violators
                    '''
                    add_to_pool()
                    cache()

        # Next address to continue search from
        curr_site = save + 1
return True
```

Essentially: find all gadget sites using regex matching, count backwards, and add the gadget to the pool if no violations occur. It really is that simple!

<a name="analysis"></a>
### Gadget Analyzer
The most attractive feature of this tool, which also acts as the backbone behind semantic searching, is the gadget analyzer. In abstract, the gadget analyzer works by creating a small, contextualized [Unicorn](https://www.unicorn-engine.org/) emulation for the gadget, hooking instruction steps and CPU exceptions, and handling errors as they come. The method chosen of "dealing with bad things as bad things happen" was purposeful in order to keep emulations as small as possible and as fast as possible. Essentially, more stuff is added to the emulation only if it is needed and since we are dealing with a small amount of instructions and many emulations can be initialized at a time via selection scrolling, this seems like the smartest solution to a stupid problem.

<a name="analysis-initialization"></a>
#### Step 1: Initialization
First initialization occurs. During this phase an emulation context for the passed gadget is created. This is a "partial" context, as context building may be applied during the emulation depending on the gadget. This includes setting up registers according to the prestate configuration, creating a small code section for the gadget and creating a stack, which notably contains cyclic data. The reasoning behind this is so that it is easier to tell during analysis if a register is corrupted with stack data and derive the offset of controlled corruption using cyclic pattern matching. It is also useful for detecting corruption in general and recovering using the last, non-cyclic value. After configuring registers, mappings, setting the permissions of and writing the latter segments, and adding unicorn hooks, the emulation is ready. Note that the hooks are the most important aspect of this analysis framework. They let us do analysis, harness CPU violations, and allow for contextualizing the memory state in realtime.

There are three hooks:
- Code hook — executes after the current instruction is fetched and before it is executed
- Memory violation hook — executes when unmapped memory is fetched
- Interrupt hook — executes when a CPU interruption has occurred (simply aborts)

<a name="analysis-context"></a>
#### Step 2: Emulation and Realtime Contextualizing
Now that the partial gadget context is created and exceptions have been harnessed, emulation is ready to begin. One of the reasons Unicorn was chosen over other emulation frameworks is because it is lightweight and contextless. This gives us the benefit of being able to create lightweight emulations with a small amount of memory mappings. However, this also means that we are unable to emulate interrupts and syscalls and that gadget execution sometimes does not accurately reflect the true binary context.

For example, consider the following gadget:
`mov [r14], r15 ; ret ;`

This gadget moves the value of `r15` into the dereferenced location of `r14`. There are two issues here, one of which we can handle gracefully.
Issue A: `r14` could point to memory that is statically mapped into the binary (e.g., .text, .data, .got, etc.) of which we could resolve. 
Issue B: Alternatively, `r14` could point to memory that is dynamic, randomly based with ASLR and purely dependent on runtime context.

The first situation we can handle in a gracefully stupid way. The second is a little harder and is not supported at this time, however I plan to allow corefile imports in the future, which will handle this scenario. In either case, both of these scenarios would result in failure as the CPU tries to fetch unmapped memory. This is where the memory violation hook comes into play. One of the steps that occurs before emulation actually starts, but as a part of the emulation function, is a check in a queue of mappings. If this list contains any mapping, it is resolved using helper functions and then dequeued. This is done by resolving the nearest page-aligned boundary that overlaps the target address. Then emulation will continue.

![](/assets/posts/2024-06-02/diagram_resolve.png)

The memory hook simply catches fetch violations, analyzes the dereferenced area by comparing it to mapped memory in the binary and sets an error code (which can be recoverable or non-recoverable). If the situation is recoverable via resolving then the mapping is enqueued. If the situation is not recoverable, -1 is inserted at index 0, which will direct the emulation handler to stop execution and generate an error description. Some examples of errors that are not recoverable are trying to execute mapped, non-executable memory or a null dereference. From this point on, in both cases, emulation is stopped and the handler is recursively called. The emulation handler also deals with side cases, like stack pivots, before recursion so that emulation can continue properly.

<a name="analysis-stepthru"></a>
#### Step 3: Step-thru Analysis
The code hook is responsible for doing analysis and diffing at each execution cycle. This hook is after the next instruction is fetched, but before it executes. It is responsible for both saving various components of the current memory state (in case weird corruption occurs we can recover using these components) and saving analysis. Analysis information is saved in a list, where every index corresponds to the index of an instruction in a gadget and each element represents a dictionary of the memory state at that time of execution.

For example:

```
Gadget:
pop rdi ; mov rsi, 0x3 ; ret ;

Analysis:
[{rdi:'Full control'}, {rsi:3}]
```

The end state (used for both display and semantic queries) is simply derived from `analysis_steps[-1]`. Additionally, the saved previous program state is used for register diffing next time the step hook is called. At any point during emulation when the code hook is called there will exist a `last_program_state` that the current context will reference for recovery options and diffing.

![](/assets/posts/2024-06-02/diagram_analysis.png)

<a name="search"></a>
### Semantic Search Filters
The search filter is unique to other tools, not just for its semantic searching capabilities, but for its handling and logical parsing of queries in general.

![](/assets/posts/2024-06-02/semantic_search_demo.gif)

The gadget pool DataFrame is derived from the gadget pool cache, which is stored in the session. The pool contains all gadgets (including duplicates), regardless of options. Options constrain what is displayed via GadgetRender and do not actually affect the gadget cache. The gadget pool DataFrame, like the cache, will contain every gadget found.

Primary queryable columns:
- Address (unsigned long)
- Bytes (string)
- Disasm (string)
- inst_cnt (int64)
- All registers (each an unsigned long)

Semantic querying is done in three steps:
1. Query translation
2. DataFrame transformation
3. DataFrame querying

Example translation:

```
Semantic search value: rax>0x3b
Translation: ((rax>0x3b or (rax==CONTROL_SENTINEL)) and not rax==UNINITIALIZED_SENTINEL)
```

The control sentinel value represents a register which analysis determines we have full control of (such as a popped register). We'd want to include these in the search results, since we can use these to make a register equal any value and thus it would always match any query. Additionally, we exclude the uninitialized sentinel because this sentinel value also represents unclobbered registers. After the query is built, we transform a subsection of the DataFrame by resolving analysis states from addresses in a sub-frame to the main frame until the semantic depth limit is reached.

![](/assets/posts/2024-06-02/dataframe.png)

Presets are translated into static queries or queries tied to specific architecture constants.

![](/assets/posts/2024-06-02/sc5.png)

<a name="closing"></a>
### Closing
That's my tool! I hope you enjoyed this technical post describing it, which I believe was well worth writing considering the interesting algorithms and techniques that this tool adapts to do what it does. Although in retrospect, my code is not the cleanest or most optimized, I believe it is optimized enough and that some novel techniques are utilized to make it run fast with accurate results. Furthermore, this tool is an open-source plugin, so if you'd like to add a component, feature or modify existing structures, I encourage you to make a PR! I plan to actively maintain this project in the foreseeable future; specific developments I have planned can be found on the repo, but updates might be far between because of other priorities. If you've enjoyed this post please share it with your pwn-pals and do let me know if you're enjoying the tool. Thank you!