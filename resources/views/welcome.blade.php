<x-layout>
    <div class="mt-48 flex flex-col items-center justify-center">
        @auth
            <h1 class="text-7xl text-center my-auto">You are logged in</h1>
        @else
            <h1 class="text-7xl text-center my-auto">Welcome to Form App</h1>
        @endauth
    </div>
</x-layout>
